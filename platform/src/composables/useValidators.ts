import { isValidEmail } from '@/plugins/helpers';
import { i18n } from '@/plugins/i18n';

export function useValidators() {

  const emailFieldRules: Array<(value: string) => boolean | string> = [
    value => !!value || i18n.global.t('form.email.errors.required'),
    value => isValidEmail(value) || i18n.global.t('form.email.errors.invalid')
  ];

  const passwordRequired = (value: string) => !!value || i18n.global.t('form.password.errors.required')

  return {
    emailFieldRules,
    passwordRequired,
  }
}