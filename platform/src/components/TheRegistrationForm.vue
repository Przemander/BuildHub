<script setup lang="ts">
import { ref, reactive, computed, onBeforeUnmount } from 'vue';
import { mdiEye, mdiEyeOff, mdiAt, mdiKey } from '@mdi/js';
import { useAuthentication } from '../composables/useAuthentication';
import { type RegistrationFormInterface } from '@/types';
import { useTheme } from '@/composables/useTheme';
import { Checkbox } from 'vue-recaptcha/head';
import { useValidators } from '@/composables/useValidators';
import { useAppStatute } from '@/composables/useAppStatute';
import { useSnackbar } from '@/composables/useSnackbar';
import { useRouter } from "vue-router";
import { i18n } from '@/plugins/i18n';

const { setNotification } = useSnackbar();
const { openAppStatuteDialog, isStatuteAccepted } = useAppStatute();
const { register } = useAuthentication();
const { emailFieldRules } = useValidators();
const { theme } = useTheme();
const router = useRouter();

const isFormValid = ref<boolean | null>(false);
const timeout = ref<number>(0);

const form = reactive<RegistrationFormInterface>({
  email: null,
  password: null,
  password_confirmation: null,
  recaptcha_token: null,
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
      await register(form);
      setNotification(i18n.global.t('register.success.link_sent'), 'success')
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


const handleClick = (event: any): void => {
  if (event.target.classList.contains('statute-link')) {
    openAppStatuteDialog();
  }
}

const isPasswordVisible = ref<boolean>(false);
</script>
<template>
  <v-form class="px-sm-10" v-model="isFormValid" @submit.prevent="submit">
    <v-text-field v-model="form.email" :rules="emailFieldRules" :label="i18n.global.t('form.email.label')" density="compact"
      :placeholder="i18n.global.t('form.email.placeholder')" :prepend-inner-icon="mdiAt" variant="outlined"
      required></v-text-field>

    <v-text-field :focused="true" v-model="form.password" :label="i18n.global.t('form.password.label')"
      :append-inner-icon="isPasswordVisible ? mdiEyeOff : mdiEye" :type="isPasswordVisible ? 'text' : 'password'"
      density="compact" class="my-4" :placeholder="i18n.global.t('form.password.placeholder')"
      :prepend-inner-icon="mdiKey" variant="outlined" @click:append-inner="isPasswordVisible = !isPasswordVisible"
      :error="!!passwordError" :error-messages="passwordError"></v-text-field>

    <v-text-field v-model="form.password_confirmation" class="mb-4"
      :label="i18n.global.t('form.password.label')"
      :append-inner-icon="isPasswordVisible ? mdiEyeOff : mdiEye" :type="isPasswordVisible ? 'text' : 'password'"
      density="compact" :placeholder="i18n.global.t('form.password.placeholder')"
      :prepend-inner-icon="mdiKey" variant="outlined" @click:append-inner="isPasswordVisible = !isPasswordVisible"
      :error="!!confirmationError" :error-messages="confirmationError"></v-text-field>

    <Checkbox :key="theme" v-model="form.recaptcha_token" :theme="theme" />

    <v-checkbox v-model="isStatuteAccepted" class="mt-4">
      <template v-slot:label>
        <div v-html="i18n.global.t('statute.label')" @click="handleClick" />
      </template>
    </v-checkbox>

    <v-btn :disabled="!isFormValid || !form.recaptcha_token || !isStatuteAccepted" type="submit" class="mb-8"
      color="blue" size="large" variant="tonal" block>
      {{ i18n.global.t('register.button.label') }}
    </v-btn>
  </v-form>
</template>