import { ref, type Ref } from 'vue';
import AxiosInstance from '../config/axios';
import { type ForgotPasswordFormInterface, type ResetPasswordFormInterface } from '@/types';
import { useSnackbar } from '@/composables/useSnackbar';
import { i18n } from '@/plugins/i18n';

const { setNotification } = useSnackbar();

const isForgotPasswordModalVisible: Ref<boolean> = ref(false);

export function useForgotPassword() {

  const forgotPassword = async (form: ForgotPasswordFormInterface): Promise<void> => {
    try {
      await AxiosInstance.post('/forgot-password', { ...form });
      setNotification(i18n.global.t('forgot_password.success.link_sent'), 'success')
    } catch (error) {
      console.log(error);
    }
  }

  const resetPassword = async (formData: ResetPasswordFormInterface): Promise<void> => {
    try {
      await AxiosInstance.post('/reset-password', { ...formData });
      setNotification(i18n.global.t('forgot_password.success.reset'), 'success')
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  return {
    isForgotPasswordModalVisible,
    forgotPassword,
    resetPassword
  }
}