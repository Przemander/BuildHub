<template>
  <v-container>
    STRONA GÓWNA
  </v-container>
  <v-dialog v-model="isLoginDialogVisible" max-width="400" transition="dialog-bottom-transition">
    <TheLoginForm />
  </v-dialog>
</template>

<script setup lang="ts">
import { useAuthentication } from '@/composables/useAuthentication';
import TheLoginForm from '@/components/TheLoginForm.vue';

const { isLoginDialogVisible } = useAuthentication();
</script>