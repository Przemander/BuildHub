import { i18n } from '@/plugins/i18n';
import { errorMessages } from './errors';

export function isValidEmail(email: string): boolean {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

export function extractErrorMessage(error: any, fallback: string): string {
  const code = error?.response?.data?.code;
  const defaultMsg = fallback || i18n.global.t('errors.generic.unknown');

  if (code && code in errorMessages) {
    return i18n.global.t(errorMessages[code as keyof typeof errorMessages]);
  }

  const apiMessage = error?.response?.data?.message;
  if (apiMessage && typeof apiMessage === 'string') {
    return apiMessage;
  }

  return defaultMsg;
}