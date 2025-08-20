<script setup lang="ts">
import { RouterView } from 'vue-router';
import { useTheme } from '@/composables/useTheme';
import { useSnackbar } from '@/composables/useSnackbar';
import { useRecaptchaProvider } from 'vue-recaptcha/head';
import TheHeader from '@/components/TheHeader.vue';
import TheFooter from '@/components/TheFooter.vue';

const { fillFromStorage: setThemeFromStorage, theme } = useTheme();
const { message, messageType, isSnackbarVisible, clearNotification } = useSnackbar();

useRecaptchaProvider();
setThemeFromStorage();
</script>

<template>
  <v-app :theme="theme" :class="'bg-' + theme">
    <TheHeader />
    <v-main class="d-flex flex-grow-1">
      <RouterView />
    </v-main>
    <TheFooter />
    <v-snackbar v-model="isSnackbarVisible" variant="flat" location="top" :color="messageType as string" timeout="3000"
      position="fixed" timer="true" @update:model-value="value => { if (!value) clearNotification() }">
      {{ message }}
    </v-snackbar>
  </v-app>
</template>

<style lang="scss" scoped>
.bg-dark {
  min-height: 100vh;
  background-color: #0f1c14;

  background-image:
    radial-gradient(at top right, #009b6f, transparent 50%),
    radial-gradient(at bottom left, #1b9092, transparent 50%);

  background-repeat: no-repeat;
}

.bg-light {
  min-height: 100vh;
  background-color: #fff;

  background-image:
    radial-gradient(at top right, rgba(0, 255, 170, 0.3), transparent 50%),
    radial-gradient(at bottom left, rgba(4, 255, 159, 0.3), transparent 50%);

  background-repeat: no-repeat;
}
</style>
