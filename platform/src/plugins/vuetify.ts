import '@mdi/font/css/materialdesignicons.css';
import 'vuetify/styles';

import { createVuetify, type ThemeDefinition } from 'vuetify';
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg';

const light: ThemeDefinition = {
  dark: false,
  colors: {
    background: '#FFFFFF',
    surface: 'rgb(230,230,230)',
    primary: 'rgb(100,100,255)',
    'primary-lighten-1': 'rgb(212, 212, 255)',
    'primary-darken-1': 'rgb(212, 212, 255)',
    secondary: 'rgb(173, 170, 255)',
    'secondary-lighten-1': 'rgb(206, 206, 206)',
    'secondary-darken-1': 'rgb(8, 0, 228)',
    error: '#B00020',
    info: '#2196F3',
    success: '#4CAF50',
    warning: '#FB8C00',
  },
}

const dark: ThemeDefinition = {
  dark: true,
  colors: {
    surface: '#000000',
    primary: '#00aa61ff',
    'primary-lighten-1': '#00cf75ff',
    'primary-darken-1': '#007e48ff',
    secondary: "#283593",
    'secondary-lighten-1': 'rgb(197, 205, 255)',
    'secondary-darken-1': 'rgb(0, 184, 216)',
    info: '#BBDEFB',
  },
}

export default createVuetify({
  icons: {
    defaultSet: 'mdi',
    aliases,
    sets: {
      mdi,
    },
  },
  theme: {
    themes: {
      light,
      dark
    }
  }
})
