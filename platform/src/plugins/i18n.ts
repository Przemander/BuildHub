import { createI18n } from 'vue-i18n'

import en from '@/locales/en.json'
import pl from '@/locales/pl.json'

export const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  globalInjection: true,
  messages: {
    en,
    pl,
  }
})
