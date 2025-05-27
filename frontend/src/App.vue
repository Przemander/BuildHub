<template>
  <div id="app">
    <header>
      <h1>BuildHub</h1>
    </header>
    <main>
      <RegisterForm />
    </main>
  </div>
</template>

<script>
import RegisterForm from './components/RegisterForm.vue';

export default {
  name: 'App',
  components: {
    RegisterForm
  }
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}

header {
  margin-bottom: 30px;
}

main {
  max-width: 800px;
  margin: 0 auto;
}
</style>
