<script setup lang="ts">
import { i18n } from '@/plugins/i18n';
import { mdiInformationOutline, mdiWindowClose } from '@mdi/js';
import { useAppStatute } from '@/composables/useAppStatute';

const { closeAppStatuteDialog } = useAppStatute();

</script>

<template>
  <v-card class="mb-4">
    <v-btn class="position-absolute top-0 right-0 mt-2 mr-2 z-index-1" variant="text"
      @click="closeAppStatuteDialog()">
      <v-icon :icon="mdiWindowClose"></v-icon>
    </v-btn>
    <v-card-title class="text-center">
      <v-icon class="mr-4" :icon="mdiInformationOutline"></v-icon>
      {{ i18n.global.t('statute.header') }}
    </v-card-title>
    <v-card-text>
      <v-list dense>
        {{ i18n.global.t('statute.subheader') }}
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">
            {{ i18n.global.t('statute.introduction.label') }}
          </v-list-item-title>
          {{ i18n.global.t('statute.introduction.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">
            {{ i18n.global.t('statute.account_registration.label') }}
          </v-list-item-title>
          {{ i18n.global.t('statute.account_registration.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">
            {{ i18n.global.t('statute.processing_data.label') }}
          </v-list-item-title>
          {{ i18n.global.t('statute.processing_data.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">
            {{ i18n.global.t('statute.google_analytics.label') }}
          </v-list-item-title>
          {{ i18n.global.t('statute.google_analytics.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">{{ i18n.global.t('statute.cookies.label') }}</v-list-item-title>
          {{ i18n.global.t('statute.cookies.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">
            {{ i18n.global.t('statute.security.label') }}
          </v-list-item-title>
          {{ i18n.global.t('statute.security.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">
            {{ i18n.global.t('statute.terms_changes.label') }}
          </v-list-item-title>
          {{ i18n.global.t('statute.terms_changes.value') }}
        </v-list-item>
        <v-divider color="info"></v-divider>
        <v-list-item class="py-5 px-2">
          <v-list-item-title class="text-h5">{{ i18n.global.t('statute.contact.label') }}</v-list-item-title>
          {{ i18n.global.t('statute.contact.value') }}
        </v-list-item>
      </v-list>
    </v-card-text>
  </v-card>
</template>
