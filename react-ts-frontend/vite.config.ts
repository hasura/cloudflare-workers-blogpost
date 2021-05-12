import reactRefresh from "@vitejs/plugin-react-refresh"
import * as dotenv from "dotenv"
import { defineConfig } from "vite"

// Terrible hack required while this PR waiting to be merged:
// https://github.com/vitejs/vite/pull/2123
const result = dotenv.config({
  debug: true,
  //@ts-ignore
  path: require("path").join(__dirname, "../.env"),
})
if (result.error) throw result.error

const defines = {}
//@ts-ignore
for (let key in result.parsed) {
  //@ts-ignore
  if (!key.startsWith("VITE_")) continue
  defines["import.meta.env." + key] = JSON.stringify(result.parsed[key])
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [reactRefresh()],
  define: defines,
})
