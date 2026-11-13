import { ref, shallowRef } from 'vue'
import { defineStore } from 'pinia'
import { previewSandboxMask } from '@/api/sandbox'
import { GOLDEN_GOV_QA_STRUCTURED, GOLDEN_GOV_QA_TEXT } from '@/constants/domain'
import type { SandboxPreviewRequest, SandboxPreviewResponseData } from '@/types/api'

/**
 * Pure in-memory ephemeral sandbox store.
 * Zero-Client-Persistence Rule: NEVER persisted to localStorage, sessionStorage,
 * IndexedDB, URL query parameters, or console logs. Cleared on view unmount.
 */
export const useSandboxStore = defineStore('sandbox', () => {
  const mode = ref<'TEXT' | 'STRUCTURED'>('TEXT')
  const policyCode = ref<string>('gov_eval_corpus')
  const policyVersion = ref<number>(0)
  const inputText = ref<string>('')
  const structuredJsonText = ref<string>('')
  const result = shallowRef<SandboxPreviewResponseData | null>(null)
  const running = ref<boolean>(false)
  const errorMessage = ref<string>('')

  function fillGoldenSample(): void {
    errorMessage.value = ''
    if (mode.value === 'TEXT') {
      inputText.value = GOLDEN_GOV_QA_TEXT
    } else {
      structuredJsonText.value = JSON.stringify(GOLDEN_GOV_QA_STRUCTURED, null, 2)
    }
  }

  function clearInputs(): void {
    inputText.value = ''
    structuredJsonText.value = ''
    result.value = null
    errorMessage.value = ''
  }

  function clearSensitiveState(): void {
    inputText.value = ''
    structuredJsonText.value = ''
    result.value = null
    errorMessage.value = ''
    running.value = false
  }

  async function runPreview(parsedPayload?: Record<string, unknown>): Promise<void> {
    errorMessage.value = ''
    running.value = true
    try {
      const req: SandboxPreviewRequest = {
        mode: mode.value,
        policy_code: policyCode.value || undefined,
        policy_version: policyVersion.value > 0 ? policyVersion.value : null,
      }
      if (mode.value === 'TEXT') {
        req.text = inputText.value
      } else {
        req.payload = parsedPayload
      }
      result.value = await previewSandboxMask(req)
    } finally {
      running.value = false
    }
  }

  return {
    mode,
    policyCode,
    policyVersion,
    inputText,
    structuredJsonText,
    result,
    running,
    errorMessage,
    fillGoldenSample,
    clearInputs,
    clearSensitiveState,
    runPreview,
  }
})
