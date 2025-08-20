<script setup lang="ts">
import TheLoginForm from '@/components/TheLoginForm.vue';
import { useRoute } from 'vue-router';
import { useSnackbar } from '@/composables/useSnackbar';
import { i18n } from '@/plugins/i18n';

const { setNotification } = useSnackbar();
const route = useRoute();

if (route.query.verified) {
  setNotification(i18n.global.t('auth.account_activated'), 'success')
}
</script>

<template>
  <v-container>
    <v-row class="fill-height">
      <v-col cols="12" lg="6" class="flex-column justify-center align-center d-flex">
        <UploadFile />
      </v-col>
      <v-col cols="12" lg="6" class="flex-column justify-center align-center d-flex">
        <TheLoginForm />
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.LoginView {
  padding: 3rem;
  display: flex;
  justify-content: center;
}

.LoginView .LoginView__form-container {
  width: 40vw;
  padding: 0 10rem
}

.LoginView .LoginView__form-container label,
.form-button {
  display: inline-block;
  margin: 0 auto
}
</style>
