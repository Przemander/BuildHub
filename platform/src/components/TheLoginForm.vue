<script setup lang="ts">
import { ref, reactive, type Ref, type Reactive } from 'vue';
import TheForgotPasswordForm from './TheForgotPasswordForm.vue';
import { mdiEye, mdiEyeOff, mdiAt, mdiKey } from '@mdi/js';
import { useAuthentication } from '@/composables/useAuthentication';
import { useRouter } from "vue-router";
import { useValidators } from '@/composables/useValidators';
import { useForgotPassword } from '@/composables/useForgotPassword';
import { type LoginFormInterface } from '@/types';
import { i18n } from '@/plugins/i18n';

const router = useRouter();
const { login } = useAuthentication();
const { emailFieldRules, passwordRequired } = useValidators();
const { isForgotPasswordModalVisible } = useForgotPassword();

const isPasswordVisible: Ref<boolean> = ref(false);
const isFormValid: Ref<boolean | null> = ref(false);

const form: Reactive<LoginFormInterface> = reactive({
  email: null,
  password: null,
});

const submit = async (): Promise<void> => {
  if (isFormValid.value) {
    try {
      await login(form);
      router.push({ name: "files" });
    } catch (error) {
      console.log(error);
    }
  }
}
</script>
<template>
  <v-card color="primary-darken-1" class="mx-auto pa-3 pa-sm-6 pa-lg-12 w-100" elevation="8" max-width="500" rounded="lg"
    :title="i18n.global.t('login.title')">
    <v-card class="mb-12" color="surface-variant" variant="tonal">
      <v-card-text class="text-medium-emphasis text-caption">
        {{ i18n.global.t('login.subtitle') }}
      </v-card-text>
    </v-card>
    <v-form v-model="isFormValid" class="d-flex flex-column" @submit.prevent="submit">

      <v-text-field v-model="form.email" :rules="emailFieldRules" :label="i18n.global.t('form.email.label')"
        density="compact" :placeholder="i18n.global.t('form.email.placeholder')"
        :prepend-inner-icon="mdiAt" variant="outlined"></v-text-field>

      <v-btn variant="text" class="text-blue text-caption align-self-start"
        @click="isForgotPasswordModalVisible = true">
        {{ i18n.global.t('forgot_password.triggering_button.label') }}
      </v-btn>

      <v-text-field v-model="form.password" :rules="[passwordRequired]"
        :append-inner-icon="isPasswordVisible ? mdiEyeOff : mdiEye" :type="isPasswordVisible ? 'text' : 'password'"
        :label="i18n.global.t('form.password.label')" density="compact"
        :placeholder="i18n.global.t('form.password.placeholder')" :prepend-inner-icon="mdiKey"
        variant="outlined" @click:append-inner="isPasswordVisible = !isPasswordVisible"></v-text-field>

      <v-btn :disabled="!isFormValid" type="submit" class="mt-4" color="primary" size="large" variant="elevated" block>
        {{ i18n.global.t('login.button.label') }}
      </v-btn>
      <div class="d-flex align-center my-4">
        <v-divider class="flex-grow-1"></v-divider>
        <span class="mx-4 text-medium-emphasis">{{ i18n.global.t('login.divider.label') }}</span>
        <v-divider class="flex-grow-1"></v-divider>
      </div>

      <v-btn color="secondary" class="text-blue mx-auto" @click="router.push({ name: 'registration' })">
        {{ i18n.global.t('register.triggering_button.label') }}
      </v-btn>
    </v-form>
  </v-card>
  <v-dialog v-model="isForgotPasswordModalVisible" max-width="650">
    <TheForgotPasswordForm />
  </v-dialog>
</template>

<style lang="sass" scoped>
</style>