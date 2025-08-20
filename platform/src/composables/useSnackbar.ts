import { ref, type Ref } from 'vue';

const message: Ref<string | null> = ref(null);
const messageType: Ref<'success' | 'error' | null> = ref('error');
const isSnackbarVisible: Ref<boolean> = ref(false);

export function useSnackbar() {

  const setNotification = (notification: string, type: 'success' | 'error' = 'error'): void => {
    message.value = notification;
    messageType.value = type;
    isSnackbarVisible.value = true;
  }

  const clearNotification = (): void => {
    message.value = null;
    messageType.value = null;
    isSnackbarVisible.value = false;
  }

  return {
    setNotification,
    clearNotification,
    isSnackbarVisible,
    message,
    messageType
  }
}