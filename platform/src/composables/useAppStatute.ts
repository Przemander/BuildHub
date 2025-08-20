import { ref, type Ref } from 'vue';

const isStatuteAccepted: Ref<boolean> = ref(false);
const isStatuteDialogVisible: Ref<boolean> = ref(false);

export function useAppStatute() {

  const openAppStatuteDialog = () => {
    isStatuteDialogVisible.value = true;
  }

  const closeAppStatuteDialog = () => {
    isStatuteDialogVisible.value = false;
  }

  return {
    isStatuteAccepted,
    isStatuteDialogVisible,
    openAppStatuteDialog,
    closeAppStatuteDialog
  }
}