import '@mdi/font/css/materialdesignicons.css';
import 'vuetify/styles';

import { createVuetify, type ThemeDefinition } from 'vuetify';
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg';

const light: ThemeDefinition = {
  dark: false,
  colors: {
    background: '#FFFFFF',
    surface: 'rgb(230,230,230)',
    primary: 'rgba(62, 202, 3, 1)',
    'primary-lighten-1': 'rgba(80, 255, 5, 1)',
    'primary-darken-1': 'rgba(54, 181, 0, 1)',
    secondary: 'rgba(219, 227, 1, 1)',
    'secondary-lighten-1': 'rgba(247, 255, 3, 1)',
    'secondary-darken-1': 'rgba(178, 184, 0, 1)',
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
