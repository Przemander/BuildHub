<script setup lang="ts">
import TheRegistrationForm from '@/components/TheRegistrationForm.vue';
import TheStatute from '@/components/TheStatute.vue';
import { useAppStatute } from '@/composables/useAppStatute';
import { i18n } from '@/plugins/i18n';

const { isStatuteDialogVisible } = useAppStatute();

</script>

<template>
  <v-container class="d-flex align-center">
    <v-card color="primary-darken-1" class="mx-auto pa-12 pb-8" elevation="8" max-width="600" rounded="lg">
      <v-card-title>
        {{ i18n.global.t('register.title') }}
      </v-card-title>
      <v-card class="mb-12" color="surface-variant" variant="tonal">
        <v-card-text class="text-medium-emphasis text-caption">
          {{ i18n.global.t('register.subtitle') }}
        </v-card-text>
      </v-card>
      <TheRegistrationForm />
    </v-card>
  </v-container>
  <v-dialog v-model="isStatuteDialogVisible" max-width="800" scrollable>
    <TheStatute />
  </v-dialog>
</template>

<style scoped></style>
