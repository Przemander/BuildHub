<script setup lang="ts">
import { ref, reactive, type Ref, type Reactive, onBeforeUnmount } from 'vue';
import { type ForgotPasswordFormInterface } from '@/types';
import { Checkbox } from 'vue-recaptcha/head';
import { useValidators } from '@/composables/useValidators';
import { useTheme } from '@/composables/useTheme';
import { mdiWindowClose, mdiAt } from '@mdi/js';
import { useForgotPassword } from '@/composables/useForgotPassword';
import { i18n } from '@/plugins/i18n';
import { useRouter } from "vue-router";

const { emailFieldRules } = useValidators();
const { theme } = useTheme();
const { isForgotPasswordModalVisible, forgotPassword } = useForgotPassword();
const router = useRouter();

const isFormValid: Ref<boolean | null> = ref(false);
const timeout = ref<number>(0);

const form: Reactive<ForgotPasswordFormInterface> = reactive({
  email: null,
  recaptcha_token: null,
});

const submit = async (): Promise<void> => {
  if (isFormValid.value) {
    await forgotPassword(form);
    timeout.value = setTimeout(() => {
      router.go(0);
    }, 3000);
  }
};

onBeforeUnmount(() => {
  clearTimeout(timeout.value);
})

</script>
<template>
  <v-card class="mb-4 rounded-lg px-10 py-6" variant="elevated" :title="i18n.global.t('forgot_password.title')"
    :subtitle="i18n.global.t('forgot_password.subtitle')">

    <v-btn class="position-absolute top-0 right-0 mt-2 mr-2 z-index-1" variant="text"
      @click="isForgotPasswordModalVisible = false">
      <v-icon :icon="mdiWindowClose"></v-icon>
    </v-btn>

    <v-form v-model="isFormValid" @submit.prevent="submit">
      <v-text-field v-model="form.email" :rules="emailFieldRules" :label="i18n.global.t('form.email.label')"
        density="compact" :placeholder="i18n.global.t('form.email.placeholder')"
        :prepend-inner-icon="mdiAt" variant="outlined" required></v-text-field>

      <Checkbox :key="theme" v-model="form.recaptcha_token" :theme="theme" />

      <v-btn :disabled="!isFormValid || !form.recaptcha_token" type="submit" class="my-8" color="blue" size="large"
        variant="elevated" block>
        {{ i18n.global.t('forgot_password.button.label') }}
      </v-btn>
    </v-form>
  </v-card>
</template>