/**
 * Shared sensitive-entity extraction and normalization helpers.
 *
 * L1 uses these helpers to capture canonical session-sensitive material from
 * trusted tool results. L3 reuses the same normalization logic to correlate
 * outbound content without maintaining a second detection system.
 */

export type SensitiveEntityType =
  | 'email'
  | 'ssn'
  | 'phone'
  | 'card_number'
  | 'account_id'
  | 'routing_number'
  | 'iban'
  | 'currency_amount'
  | 'customer_id'
  | 'secret'
  | 'connection_string';

export interface SensitiveEntity {
  readonly type: SensitiveEntityType;
  readonly rawValue: string;
  readonly canonicalValue: string;
  readonly confidence: 'high' | 'medium' | 'low';
  readonly sourceTool?: string;
  readonly fieldName?: string;
  readonly recordScope?: string;
  readonly timestamp?: number;
}

const EMAIL_PATTERN = /[\w.+-]+@[\w.-]+\.\w+/gi;
const SSN_PATTERN = /\d{3}[-\s]?\d{2}[-\s]?\d{4}/g;
const PHONE_PATTERN = /\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?(?:\d{3}[-.\s]?)?\d{4}/g;
const CREDIT_CARD_PATTERN = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
const IBAN_PATTERN = /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g;
const LABELED_ACCOUNT_PATTERN =
  /\b(?:account|acct|customer[_\s-]?id|client[_\s-]?id)[\s#:=-]*([A-Z0-9-]{6,34})\b/gi;
const LABELED_ROUTING_PATTERN = /\brouting(?:[_\s-]?number)?[\s#:=-]*(\d{9})\b/gi;
const CURRENCY_AMOUNT_PATTERN =
  /(?:\$|USD\s?)\d+(?:,\d{3})*(?:\.\d{2})?|\b\d+(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|dollars?)\b/gi;

const HIGH_CONFIDENCE_CURRENCY_FIELDS = [
  'balance',
  'accountbalance',
  'account_balance',
  'creditlimit',
  'credit_limit',
  'amount',
  'invoice',
  'invoicetotal',
  'invoice_total',
  'revenue',
  'reserve',
  'payroll',
  'wireamount',
  'wire_amount',
];

const ACCOUNT_ID_FIELDS = [
  'account',
  'accountid',
  'account_id',
  'acct',
  'acctid',
  'acct_id',
  'customerid',
  'customer_id',
];
const ROUTING_FIELDS = ['routing', 'routingnumber', 'routing_number'];

export interface SensitiveEntityContext {
  readonly fieldName?: string;
  readonly sourceTool?: string;
  readonly recordScope?: string;
  readonly timestamp?: number;
}

export function normalizeSensitiveEntity(type: SensitiveEntityType, rawValue: string): string {
  switch (type) {
    case 'email':
      return rawValue.toLowerCase();
    case 'ssn':
    case 'phone':
    case 'card_number':
    case 'routing_number':
      return digitsOnly(rawValue);
    case 'iban':
      return rawValue.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    case 'account_id':
    case 'customer_id':
      return rawValue.replace(/[^a-z0-9]/gi, '').toLowerCase();
    case 'currency_amount':
      return normalizeCurrencyAmount(rawValue);
    case 'secret':
    case 'connection_string':
      return rawValue.toLowerCase();
  }
}

export function extractSensitiveEntitiesFromText(
  text: string,
  context: SensitiveEntityContext = {},
): readonly SensitiveEntity[] {
  if (!text) {
    return [];
  }

  const entities: SensitiveEntity[] = [];

  const normalizedField = normalizeFieldName(context.fieldName);
  const directType = context.fieldName ? inferSensitiveEntityType(text, context.fieldName) : null;
  if (directType) {
    const entity = makeSensitiveEntity(directType, text, context);
    if (entity) {
      entities.push(entity);
      return dedupeEntities(entities);
    }
  }

  collectMatches(entities, text, EMAIL_PATTERN, 'email', context);
  collectMatches(entities, text, SSN_PATTERN, 'ssn', context);
  collectMatches(entities, text, PHONE_PATTERN, 'phone', context);
  collectMatches(entities, text, CREDIT_CARD_PATTERN, 'card_number', context);
  collectMatches(entities, text, IBAN_PATTERN, 'iban', context);
  collectCapturedMatches(entities, text, LABELED_ACCOUNT_PATTERN, 'account_id', context);
  collectCapturedMatches(entities, text, LABELED_ROUTING_PATTERN, 'routing_number', context);

  const currencyMatches = text.match(CURRENCY_AMOUNT_PATTERN);
  if (
    currencyMatches &&
    (shouldTreatAsCurrency(normalizedField) || looksLikeLabeledCurrencyText(text))
  ) {
    for (const match of currencyMatches) {
      const entity = makeSensitiveEntity('currency_amount', match, context);
      if (entity) {
        entities.push(entity);
      }
    }
  }

  return dedupeEntities(entities);
}

export function extractSensitiveEntitiesFromValue(
  value: unknown,
  context: SensitiveEntityContext = {},
): readonly SensitiveEntity[] {
  const entities: SensitiveEntity[] = [];
  collectEntitiesFromValue(value, entities, context, []);
  return dedupeEntities(entities);
}

export function matchesSensitiveEntityInText(entity: SensitiveEntity, text: string): boolean {
  if (!text) {
    return false;
  }

  const lowerText = text.toLowerCase();
  const digitText = digitsOnly(text);
  const alnumText = text.replace(/[^a-z0-9]/gi, '').toLowerCase();
  const financialText = normalizeFinancialText(text);

  if (lowerText.includes(entity.rawValue.toLowerCase())) {
    return true;
  }

  switch (entity.type) {
    case 'email':
      return lowerText.includes(entity.canonicalValue);
    case 'ssn':
    case 'card_number':
    case 'routing_number':
      return entity.canonicalValue.length > 0 && digitText.includes(entity.canonicalValue);
    case 'phone': {
      if (entity.canonicalValue.length > 0 && digitText.includes(entity.canonicalValue)) {
        return true;
      }
      const last7 = entity.canonicalValue.slice(-7);
      return last7.length >= 7 && digitText.includes(last7);
    }
    case 'iban':
    case 'account_id':
    case 'customer_id':
      return entity.canonicalValue.length > 0 && alnumText.includes(entity.canonicalValue);
    case 'currency_amount':
      return entity.canonicalValue.length > 0 && financialText.includes(entity.canonicalValue);
    case 'secret':
    case 'connection_string':
      return lowerText.includes(entity.canonicalValue);
  }
}

function collectEntitiesFromValue(
  value: unknown,
  entities: SensitiveEntity[],
  context: SensitiveEntityContext,
  path: readonly string[],
): void {
  if (value === null || value === undefined) {
    return;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      collectEntitiesFromValue(value[index], entities, context, [...path, String(index)]);
    }
    return;
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    for (const [key, child] of Object.entries(obj)) {
      collectEntitiesFromValue(
        child,
        entities,
        {
          ...context,
          fieldName: key,
          recordScope: [...path, key].join('.'),
        },
        [...path, key],
      );
    }
    return;
  }

  if (
    typeof value !== 'string' &&
    typeof value !== 'number' &&
    typeof value !== 'boolean' &&
    typeof value !== 'bigint'
  ) {
    return;
  }

  const stringValue = String(value);
  const extracted = extractSensitiveEntitiesFromText(stringValue, {
    ...context,
    recordScope: context.recordScope ?? path.join('.'),
  });
  entities.push(...extracted);
}

function collectMatches(
  entities: SensitiveEntity[],
  text: string,
  pattern: RegExp,
  type: SensitiveEntityType,
  context: SensitiveEntityContext,
): void {
  pattern.lastIndex = 0;
  let match = pattern.exec(text);
  while (match) {
    const entity = makeSensitiveEntity(type, match[0], context);
    if (entity) {
      entities.push(entity);
    }
    match = pattern.exec(text);
  }
}

function collectCapturedMatches(
  entities: SensitiveEntity[],
  text: string,
  pattern: RegExp,
  type: SensitiveEntityType,
  context: SensitiveEntityContext,
): void {
  pattern.lastIndex = 0;
  let match = pattern.exec(text);
  while (match) {
    const entity = makeSensitiveEntity(type, match[1], context);
    if (entity) {
      entities.push(entity);
    }
    match = pattern.exec(text);
  }
}

function inferSensitiveEntityType(
  rawValue: string,
  fieldName?: string,
): SensitiveEntityType | null {
  const normalizedField = normalizeFieldName(fieldName);
  const trimmed = rawValue.trim();

  if (ROUTING_FIELDS.includes(normalizedField) && /^\d{9}$/.test(trimmed.replace(/\D/g, ''))) {
    return 'routing_number';
  }

  if (ACCOUNT_ID_FIELDS.includes(normalizedField) && /^[A-Z0-9-]{6,34}$/i.test(trimmed)) {
    return normalizedField.includes('customer') ? 'customer_id' : 'account_id';
  }

  if (/^(?:acct|account)[a-z0-9-]{4,}$/i.test(trimmed)) {
    return 'account_id';
  }

  if (shouldTreatAsCurrency(normalizedField) && CURRENCY_AMOUNT_PATTERN.test(trimmed)) {
    CURRENCY_AMOUNT_PATTERN.lastIndex = 0;
    return 'currency_amount';
  }
  CURRENCY_AMOUNT_PATTERN.lastIndex = 0;

  if (EMAIL_PATTERN.test(trimmed)) {
    EMAIL_PATTERN.lastIndex = 0;
    return 'email';
  }
  EMAIL_PATTERN.lastIndex = 0;

  if (SSN_PATTERN.test(trimmed)) {
    SSN_PATTERN.lastIndex = 0;
    return 'ssn';
  }
  SSN_PATTERN.lastIndex = 0;

  if (PHONE_PATTERN.test(trimmed) && trimmed.replace(/\D/g, '').length >= 7) {
    PHONE_PATTERN.lastIndex = 0;
    return 'phone';
  }
  PHONE_PATTERN.lastIndex = 0;

  if (CREDIT_CARD_PATTERN.test(trimmed)) {
    CREDIT_CARD_PATTERN.lastIndex = 0;
    return 'card_number';
  }
  CREDIT_CARD_PATTERN.lastIndex = 0;

  if (IBAN_PATTERN.test(trimmed)) {
    IBAN_PATTERN.lastIndex = 0;
    return 'iban';
  }
  IBAN_PATTERN.lastIndex = 0;

  return null;
}

function makeSensitiveEntity(
  type: SensitiveEntityType,
  rawValue: string,
  context: SensitiveEntityContext,
): SensitiveEntity | null {
  const canonicalValue = normalizeSensitiveEntity(type, rawValue);
  if (canonicalValue.length === 0) {
    return null;
  }

  return {
    type,
    rawValue: rawValue.trim(),
    canonicalValue,
    confidence: confidenceForEntity(type, context.fieldName),
    ...(context.sourceTool ? { sourceTool: context.sourceTool } : {}),
    ...(context.fieldName ? { fieldName: context.fieldName } : {}),
    ...(context.recordScope ? { recordScope: context.recordScope } : {}),
    ...(context.timestamp ? { timestamp: context.timestamp } : {}),
  };
}

function confidenceForEntity(
  type: SensitiveEntityType,
  fieldName?: string,
): 'high' | 'medium' | 'low' {
  const normalizedField = normalizeFieldName(fieldName);
  if (type === 'routing_number' || type === 'iban' || type === 'card_number' || type === 'ssn') {
    return 'high';
  }

  if (type === 'currency_amount') {
    return shouldTreatAsCurrency(normalizedField) ? 'high' : 'medium';
  }

  if (type === 'account_id' || type === 'customer_id') {
    return ACCOUNT_ID_FIELDS.includes(normalizedField) ? 'high' : 'medium';
  }

  return 'high';
}

function dedupeEntities(entities: readonly SensitiveEntity[]): readonly SensitiveEntity[] {
  const seen = new Set<string>();
  const deduped: SensitiveEntity[] = [];

  for (const entity of entities) {
    const key = `${entity.type}:${entity.canonicalValue}:${entity.fieldName ?? ''}:${entity.recordScope ?? ''}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(entity);
  }

  return deduped;
}

function normalizeFieldName(fieldName?: string): string {
  return (fieldName ?? '').replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function shouldTreatAsCurrency(fieldName: string): boolean {
  return HIGH_CONFIDENCE_CURRENCY_FIELDS.includes(fieldName);
}

function looksLikeLabeledCurrencyText(text: string): boolean {
  return /\b(balance|revenue|amount|invoice|reserve|credit\s*limit|payroll|wire\s*amount)\b/i.test(
    text,
  );
}

function digitsOnly(value: string): string {
  return value.replace(/\D/g, '');
}

function normalizeCurrencyAmount(value: string): string {
  const cleaned = value
    .replace(/USD/gi, '')
    .replace(/dollars?/gi, '')
    .replace(/\$/g, '')
    .replace(/,/g, '')
    .trim();
  const numeric = Number(cleaned);
  if (!Number.isFinite(numeric)) {
    return '';
  }
  return numeric.toFixed(2);
}

function normalizeFinancialText(text: string): string {
  return text
    .replace(/USD/gi, '')
    .replace(/dollars?/gi, '')
    .replace(/\$/g, '')
    .replace(/,/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();
}
