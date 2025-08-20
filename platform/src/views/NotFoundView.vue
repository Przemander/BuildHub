<template>
  <v-container class="d-flex justify-center align-center fill-height">
    <v-empty-state size="100%" :action-text="i18n.global.t('404.button.label')" :image="image404"
      :text="i18n.global.t('404.subtitle')" :title="i18n.global.t('404.title')" @click:action="goHome()">
    </v-empty-state>
  </v-container>
</template>
<script setup lang="ts">
import image404 from '@/assets/404.svg';
import { i18n } from '@/plugins/i18n';
import { useRouter } from "vue-router";

const router = useRouter();
const goHome = (): void => {
  router.push("/");
}
</script>