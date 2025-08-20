<template>
  <v-navigation-drawer v-model="drawer" temporary class="d-md-none">
    <v-list class="d-flex flex-column h-100">
      <div class="archivo-font cursor-pointer position-relative mb-2 ml-2" style="width: 170px">
        <span class="text-primary text-h4">Buildhub</span>
      </div>
      <v-list-item to="/" :active="route.name === 'main'" active-class="text-success">
        {{ i18n.global.t('navigation.home') }}
      </v-list-item>
      <v-list-item to="/about" :active="route.name === 'about'" active-class="text-success">{{
        i18n.global.t('navigation.about') }}</v-list-item>
      <v-list-item @click="openLoginDialog()">{{
        i18n.global.t('navigation.sign_in') }}</v-list-item>
      <v-list-item class="mt-auto">
        <v-btn-toggle v-model="themeSwitch" mandatory @update:modelValue="toggleTheme">
          <v-btn :value="true" icon>
            <v-icon>{{ mdiWeatherSunny }}</v-icon>
          </v-btn>
          <v-btn :value="false" icon>
            <v-icon>{{ mdiWeatherNight }}</v-icon>
          </v-btn>
        </v-btn-toggle>
      </v-list-item>
      <v-list-item>
        <LanguageSwitcher class="d-flex" />
      </v-list-item>
    </v-list>
  </v-navigation-drawer>
  <v-app-bar>
    <v-app-bar-nav-icon class="d-md-none" @click="drawer = !drawer" />
    <v-app-bar-title class="d-none d-md-flex">
      <div class="archivo-font cursor-pointer position-relative" style="width: 170px">
        <RouterLink to="/" class="text-h4"><span class="text-primary">BuildHub</span>
        </RouterLink>
      </div>
    </v-app-bar-title>
    <template v-slot:append>
      <v-btn v-if="!isAuthenticated" :prepend-icon="mdiHome" class="d-none d-md-flex">
        <RouterLink to="/" :class="route.name === 'main' ? ['font-weight-bold', 'text-success'] : 'text-info'">
          {{ i18n.global.t('navigation.home') }}
        </RouterLink>
      </v-btn>
      <v-btn v-if="!isAuthenticated" :prepend-icon="mdiInformationVariant" class="d-none d-md-flex">
        <RouterLink to="/about" :class="route.name === 'about' ? ['font-weight-bold', 'text-success'] : 'text-info'">
          {{ i18n.global.t('navigation.about') }}
        </RouterLink>
      </v-btn>
      <v-btn v-if="!isAuthenticated" :prepend-icon="mdiAccount" class="d-none d-md-flex" @click="openLoginDialog()">
        {{ i18n.global.t('navigation.sign_in') }}
      </v-btn>
      <v-btn-toggle v-model="themeSwitch" class="d-none d-md-flex" mandatory @update:modelValue="toggleTheme">
        <v-btn :value="true" icon>
          <v-icon>{{ mdiWeatherSunny }}</v-icon>
        </v-btn>
        <v-btn :value="false" icon>
          <v-icon>{{ mdiWeatherNight }}</v-icon>
        </v-btn>
      </v-btn-toggle>
      <LanguageSwitcher variant="select" class="d-none d-md-flex ml-4" />
      <v-btn v-if="isAuthenticated" :prepend-icon="mdiLogout" :text="i18n.global.t('navigation.logout')"
        @click="logOut()"></v-btn>
    </template>
  </v-app-bar>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { mdiWeatherNight, mdiWeatherSunny, mdiInformationVariant, mdiHome, mdiLogout, mdiAccount } from '@mdi/js';
import { useTheme } from '@/composables/useTheme';
import { useAuthentication } from '@/composables/useAuthentication';
import { useRoute } from 'vue-router';
import { i18n } from '@/plugins/i18n';
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'

const route = useRoute();
const { toggle: toggleTheme, theme } = useTheme();
const { isAuthenticated, logOut, openLoginDialog } = useAuthentication();

const drawer = ref<boolean>(false);
const themeSwitch = ref<boolean>(theme.value === 'light');
</script>

<style lang="sass" scoped>
.archivo-font
  a, span
    font-family: 'Archivo', sans-serif !important

</style>
