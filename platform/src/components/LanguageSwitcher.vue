<script setup lang="ts">
import flagPl from '@/assets/pl.png';
import flagGb from '@/assets/gb.png';

const flagMap = {
  pl: flagPl,
  en: flagGb,
};

import { ref } from 'vue';
import { i18n } from '@/plugins/i18n';
import { useLocalStorage } from '../composables/useLocalStorage';

const { save, get } = useLocalStorage();

const { variant = 'normal' } = defineProps<{
  variant?: 'normal' | 'select'
}>();

type LanguageCode = 'pl' | 'en';

const supportedLanguages: LanguageCode[] = ['pl', 'en'];

const items: { value: LanguageCode; title: string }[] = [
  { value: 'pl', title: 'Polski' },
  { value: 'en', title: 'English' },
];

const selectedLanguage = ref<LanguageCode>(i18n.global.locale.value);

const toggle = (language: LanguageCode): void => {
  i18n.global.locale.value = language;
  save('language', language);
}

const fillFromStorage = (): void => {
  const langFromStorage = get('language');
  if (typeof langFromStorage === 'string' && supportedLanguages.includes(langFromStorage as LanguageCode)) {
    i18n.global.locale.value = langFromStorage as LanguageCode;
    selectedLanguage.value = langFromStorage as LanguageCode;
  }
};

const handleSelectLanguage = (language: LanguageCode): void => {
  selectedLanguage.value = language;
  toggle(language);
}

fillFromStorage();
</script>
<template>
  <v-container v-if="variant !== 'select'" class="pa-2 justify-start flex-wrap">
    <img class="cursor-pointer ma-1" style="width:25px" :class="i18n.global.locale.value === 'en' ? 'active' : ''"
      :src="flagMap['en']" @click="handleSelectLanguage('en')" />
    <img class="cursor-pointer ma-1" style="width:25px" :class="i18n.global.locale.value === 'pl' ? 'active' : ''"
      :src="flagMap['pl']" @click="handleSelectLanguage('pl')" />
  </v-container>
  <v-select v-else class="align-center justify-center" v-model="selectedLanguage" :items="items" item-title="title"
    item-value="value" @update:modelValue="toggle">
    <!-- Lista rozwijana -->
    <template v-slot:item="{ item, props }">
      <div v-bind="props" class="d-flex align-center px-2 py-1 cursor-pointer">
        <img :src="flagMap[item.value as keyof typeof flagMap]" alt="flag" class="mr-2" style="width: 20px" />
        <span>{{ item.title }}</span>
      </div>
    </template>

    <!-- Wybrana opcja -->
    <template v-slot:selection="{ item }">
      <div class="d-flex align-center">
        <img :src="flagMap[item.value as keyof typeof flagMap]" alt="flag" class="mx-2" style="width: 25px" />
      </div>
    </template>
  </v-select>
</template>