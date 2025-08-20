<script setup lang="ts">
import { i18n } from '@/plugins/i18n';

</script>

<template>
  <v-container>
    <v-card variant="text">
      <v-card-text class="text-h3 text-center">{{ i18n.global.t("about.title") }}</v-card-text>
      <v-card-text class="text-subtitle-1 text-center">
        {{ i18n.global.t("about.subtitle") }}
      </v-card-text>
    </v-card>
  </v-container>
</template>

<style lang="sass" scoped>
.video-wrapper 
  position: relative
  width: 100%
  padding-bottom: 56.25%
  /* 16:9 ratio */
  height: 0
  overflow: hidden

.video-wrapper iframe
  position: absolute
  top: 0
  left: 0
  width: 100%
  height: 100%
  border: 0
</style>
