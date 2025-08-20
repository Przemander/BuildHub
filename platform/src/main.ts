import './styles/main.css';

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { i18n } from './plugins/i18n';
import { VueRecaptchaPlugin } from 'vue-recaptcha/head';

import App from './App.vue'
import router from './router'
import vuetify from "./plugins/vuetify";

const app = createApp(App)
const reCaptchaConfig = {
  v2SiteKey: import.meta.env.VITE_RECAPTCHA_SITE_KEY,
}

app.use(createPinia()).use(i18n).use(vuetify).use(router).use(VueRecaptchaPlugin, reCaptchaConfig);

app.mount('#app')
