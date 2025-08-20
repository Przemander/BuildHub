<script setup lang="ts">
import { ref, reactive, type Ref, type Reactive, computed, onBeforeUnmount } from 'vue';
import type { ResetPasswordFormInterface } from '@/types';
import { useValidators } from '@/composables/useValidators';
import { useForgotPassword } from '@/composables/useForgotPassword';
import { mdiEye, mdiEyeOff, mdiAt, mdiKey } from '@mdi/js';
import { useRoute } from 'vue-router';
import { useRouter } from "vue-router";
import { i18n } from '@/plugins/i18n';

const { emailFieldRules } = useValidators();
const { resetPassword } = useForgotPassword();

const route = useRoute();
const router = useRouter();

const timeout = ref<number>(0);
const isFormValid: Ref<boolean | null> = ref(false);
const isPasswordVisible: Ref<boolean> = ref(false);

const form: Reactive<ResetPasswordFormInterface> = reactive({
  email: null,
  password: null,
  password_confirmation: null,
  token: route.query.token as string,
});

const confirmationError = computed(() => {
  const value = form.password_confirmation;
  if (!value) return null;
  return value === form.password ? null : i18n.global.t('form.password.errors.confirmation');
});

const passwordError = computed(() => {
  const value = form.password;
  if (!value) return null;
  if (value.length < 8) return i18n.global.t('form.password.errors.length');
  return value === form.password_confirmation ? null : i18n.global.t('form.password.errors.confirmation');
})

const submit = async (): Promise<void> => {
  if (isFormValid.value) {
    try {
      await resetPassword(form);
      timeout.value = setTimeout(() => {
        router.push("/");
      }, 3000);
    } catch (error) {
      console.log(error);
    }
  }
};

onBeforeUnmount(() => {
  clearTimeout(timeout.value);
})
</script>

<template>
  <v-container class="d-flex justify-center align-center">
    <v-card :title="i18n.global.t('forgot_password.title.main')" :subtitle="i18n.global.t('forgot_password.subtitle.main')"
      class="w-100 w-sm-80 w-md-50 pa-6">

      <v-form v-model="isFormValid" @submit.prevent="submit">
        <v-text-field v-model="form.email" :rules="emailFieldRules" :label="i18n.global.t('form.email.label')" density="compact"
          :placeholder="i18n.global.t('form.email.placeholder')" :prepend-inner-icon="mdiAt" variant="outlined" required></v-text-field>

        <v-text-field v-model="form.password" :label="i18n.global.t('form.password.label')"
          :append-inner-icon="isPasswordVisible ? mdiEyeOff : mdiEye" :type="isPasswordVisible ? 'text' : 'password'"
          density="compact" :placeholder="i18n.global.t('form.password.placeholder')" :prepend-inner-icon="mdiKey" variant="outlined"
          @click:append-inner="isPasswordVisible = !isPasswordVisible" :error="!!passwordError"
          :error-messages="passwordError"></v-text-field>

        <v-text-field v-model="form.password_confirmation" :label="i18n.global.t('form.password.label')"
          :append-inner-icon="isPasswordVisible ? mdiEyeOff : mdiEye" :type="isPasswordVisible ? 'text' : 'password'"
          density="compact" :placeholder="i18n.global.t('form.password.placeholder')" :prepend-inner-icon="mdiKey" variant="outlined"
          @click:append-inner="isPasswordVisible = !isPasswordVisible" :error="!!confirmationError"
          :error-messages="confirmationError"></v-text-field>

        <v-btn :disabled="!isFormValid" type="submit" class="mb-8" color="blue" size="large" variant="tonal" block>
          {{ i18n.global.t('forgot_password.button.label') }}
        </v-btn>
      </v-form>
    </v-card>
  </v-container>
</template>

<style scoped></style>
