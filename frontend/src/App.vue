<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from "vue"
import "./style.css"
const WS_URL = "ws://localhost:8000/ws"

const events = ref([])
const connected = ref(false)
const ws = ref(null)
const maxEvents = 500
const filterType = ref("all")
const filterReason = ref("all")
const searchQuery = ref("")
const reconnectInterval = ref(null)
const connecting = ref(false)
const lastReceived = ref(null)
const messageCount = ref(0)
const wsError = ref(null)
const rawMessages = ref([])

// Command form state
const cmdAction = ref("deny_path") // "deny_path" | "allow_path"
const cmdValue = ref("")
const cmdSubmitting = ref(false)
const cmdResult = ref(null) // { ok, status, message, sent }

// The user always works with cgroup paths. Inodes are resolved server-side
// (the server stats the path and keys the BPF denied_cgroups map on the
// inode, exactly like path_to_id() in police.c). The user never types or
// sees a raw inode number.
const API_URL = "http://localhost:8000"

const sendCommand = async () => {
  const value = cmdValue.value.trim()
  if (!value) {
    cmdResult.value = { ok: false, status: 400, message: "Caminho é obrigatório", sent: null }
    return
  }

  // Always send a path. The middleman resolves it to an inode internally
  // and forwards deny_path/allow_path to the auditor, which stats the path
  // and updates the BPF denied_cgroups map keyed by st_ino.
  const payload = { action: cmdAction.value, path: value }

  cmdSubmitting.value = true
  cmdResult.value = null
  try {
    const resp = await fetch(`${API_URL}/v1/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    const body = await resp.json()
    const ok = resp.ok && body.status !== "error"
    cmdResult.value = {
      ok,
      status: resp.status,
      message: body.message || (ok ? "Comando enviado" : "Comando falhou"),
      sent: body.sent || null,
    }
    if (ok) {
      // Refresh the denied list after a successful deny/allow command.
      await fetchDenied()
    }
  } catch (err) {
    cmdResult.value = { ok: false, status: 0, message: err.message, sent: null }
  } finally {
    cmdSubmitting.value = false
  }
}

const clearCmdResult = () => {
  cmdResult.value = null
}

const allowPath = async (path) => {
  cmdSubmitting.value = true
  cmdResult.value = null
  try {
    const resp = await fetch(`${API_URL}/v1/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "allow_path", path }),
    })
    const body = await resp.json()
    const ok = resp.ok && body.status !== "error"
    cmdResult.value = {
      ok,
      status: resp.status,
      message: body.message || (ok ? "Caminho permitido" : "Falha ao permitir caminho"),
      sent: { action: "allow_path", path },
    }
    if (ok) {
      await fetchDenied()
    }
  } catch (err) {
    cmdResult.value = { ok: false, status: 0, message: err.message, sent: null }
  } finally {
    cmdSubmitting.value = false
  }
}

// PID deny/allow form state (replaces cgroup move/remove which requires
// writing to cgroup.procs — broken under WSL2 with EBUSY).
const pidDenyValue = ref("")
const pidDenySubmitting = ref(false)
const pidDenyResult = ref(null) // { ok, status, message, sent }

// Currently denied cgroup paths (fetched from the middleman).
const deniedCgroups = ref([]) // [{ path, inode? }]
const deniedLoading = ref(false)

// Default cgroup being policed (shown to the user as the active cgroup).
const DEFAULT_CGROUP_PATH = "/sys/fs/cgroup/denied"
const activeCgroup = ref(DEFAULT_CGROUP_PATH)

// Currently denied PIDs (fetched from the middleman).
const deniedPids = ref([]) // [number]
const deniedPidsLoading = ref(false)

// cgroup.procs contents (PIDs inside the denied cgroup) — read only.
// No write/remove here because cgroup.procs writes can fail with EBUSY
// under WSL2. Use the "Negar/permitir PID (BPF)" panel instead to block
// or unblock PIDs via the BPF denied_pids map.
const cgProcsCgroup = ref(DEFAULT_CGROUP_PATH)
const cgProcsPids = ref([]) // [number]
const cgProcsLoading = ref(false)
const cgProcsError = ref(null)
const cgProcsInterval = ref(null)

// Remove a PID from the denied cgroup by moving it to the parent cgroup's
// cgroup.procs. Preserves every other PID currently listed in the source.
// Retries on EBUSY (WSL2 cgroup.v2 can be transiently busy).
const cgRemoveSubmitting = ref(false)
const cgRemovePid = ref(null) // pid currently being removed (for optimistic UI)
const cgRemoveError = ref(null)

const removeFromCgroup = async (pid, cgroupPath) => {
  cgRemoveSubmitting.value = true
  cgRemoveError.value = null
  cgRemovePid.value = pid
  try {
    const resp = await fetch(`${API_URL}/v1/cgroup/remove`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid, cgroup_path: cgroupPath }),
    })
    const body = await resp.json()
    const ok = resp.ok && body.status !== "error"
    if (ok) {
      cgProcsPids.value = cgProcsPids.value.filter((p) => p !== pid)
      await fetchDenied()
    } else {
      cgRemoveError.value = body.message || "Failed to remove PID from cgroup"
    }
  } catch (err) {
    cgRemoveError.value = err.message
    console.error("[frontend] Failed to remove PID from cgroup:", err)
  } finally {
    cgRemoveSubmitting.value = false
    cgRemovePid.value = null
  }
}

const fetchCgroupProcs = async () => {
  cgProcsLoading.value = true
  cgProcsError.value = null
  try {
    const resp = await fetch(`${API_URL}/v1/cgroup/procs?cgroup_path=${encodeURIComponent(cgProcsCgroup.value)}`)
    const body = await resp.json()
    if (body.status === "ok") {
      cgProcsPids.value = body.pids || []
    } else {
      cgProcsError.value = body.message || "Unknown error"
    }
  } catch (err) {
    cgProcsError.value = err.message
    console.error("[frontend] Failed to fetch cgroup.procs:", err)
  } finally {
    cgProcsLoading.value = false
  }
}

const startCgProcsPoll = () => {
  if (cgProcsInterval.value) return
  cgProcsInterval.value = setInterval(fetchCgroupProcs, 3000)
}

const stopCgProcsPoll = () => {
  if (cgProcsInterval.value) {
    clearInterval(cgProcsInterval.value)
    cgProcsInterval.value = null
  }
}

const fetchDenied = async () => {
  deniedLoading.value = true
  try {
    const resp = await fetch(`${API_URL}/v1/denied`)
    const body = await resp.json()
    if (body.status === "ok") {
      deniedCgroups.value = body.cgroups || []
    }
  } catch (err) {
    console.error("[frontend] Failed to fetch denied list:", err)
  } finally {
    deniedLoading.value = false
  }
}

const connectWebSocket = () => {
  if (connecting.value) {
    return
  }
  console.log("[frontend] Creating WebSocket to:", WS_URL)
  wsError.value = null
  connecting.value = true

  try {
    ws.value = new WebSocket(WS_URL)
  } catch (err) {
    console.error("[frontend] Failed to create WebSocket:", err)
    wsError.value = err.message
    connecting.value = false
    scheduleReconnect()
    return
  }

  ws.value.onopen = () => {
    console.log("[frontend] WebSocket onopen - connected")
    connected.value = true
    wsError.value = null
    connecting.value = false
    // Clear local state so the history backfill from the server starts clean
    // and we don't show duplicate/stale events after a refresh or reconnect.
    events.value = []
    rawMessages.value = []
    messageCount.value = 0
    lastReceived.value = null
    if (reconnectInterval.value) {
      clearInterval(reconnectInterval.value)
      reconnectInterval.value = null
    }
  }

  ws.value.onmessage = (event) => {
    console.log("[frontend] onmessage fired, data length:", event.data.length)
    try {
      const payload = JSON.parse(event.data)
      console.log("[frontend] Parsed payload:", payload)
      rawMessages.value.unshift({
        time: new Date().toLocaleTimeString("pt-BR"),
        data: payload,
      })
      if (rawMessages.value.length > 50) {
        rawMessages.value.pop()
      }

      // Command lifecycle messages are not BPF events; track them separately.
      if (payload.type === "CMD_SENT") {
        cmdResult.value = {
          ok: true,
          status: 200,
          message: "Command forwarded to auditor",
          sent: payload.payload,
        }
        messageCount.value = messageCount.value + 1
        lastReceived.value = new Date().toLocaleTimeString("pt-BR")
        return
      }
      if (payload.type === "CMD_ACK") {
        cmdResult.value = {
          ok: payload.success,
          status: payload.success ? 200 : 500,
          message: payload.msg || (payload.success ? "Applied by auditor" : "Rejected by auditor"),
          sent: payload.action,
        }
        messageCount.value = messageCount.value + 1
        lastReceived.value = new Date().toLocaleTimeString("pt-BR")
        return
      }

      messageCount.value = messageCount.value + 1
      lastReceived.value = new Date().toLocaleTimeString("pt-BR")

      events.value.unshift({
        ...payload,
        id: Date.now() + Math.random(),
      })
      if (events.value.length > maxEvents) {
        events.value.pop()
      }

      // Force Vue to detect the change
      void events.value.length
    } catch (err) {
      console.error("[frontend] Failed to parse event:", err, event.data)
    }
  }

  ws.value.onclose = (event) => {
    console.log("[frontend] WebSocket onclose, code:", event.code, "reason:", event.reason)
    connected.value = false
    connecting.value = false
    scheduleReconnect()
  }

  ws.value.onerror = (err) => {
    console.error("[frontend] WebSocket onerror:", err)
    wsError.value = "WebSocket connection error"
    connecting.value = false
  }
}

const scheduleReconnect = () => {
  if (reconnectInterval.value) return
  console.log("[frontend] Scheduling reconnect in 3s...")
  reconnectInterval.value = setInterval(connectWebSocket, 3000)
}

const filteredEvents = computed(() => {
  return events.value.filter((e) => {
    const typeMatch = filterType.value === "all" || e.type === filterType.value
    const reasonMatch = filterReason.value === "all" || e.reason === filterReason.value
    const query = searchQuery.value.toLowerCase()
    const searchMatch =
      !query ||
      e.comm?.toLowerCase().includes(query) ||
      e.cmd_str?.toLowerCase().includes(query) ||
      e.reason?.toLowerCase().includes(query) ||
      e.cgid?.toString().includes(query) ||
      e.pid?.toString().includes(query)
    return typeMatch && reasonMatch && searchMatch
  })
})

const stats = computed(() => {
  const total = events.value.length
  const police = events.value.filter((e) => e.type === "POLICE").length
  const audit = events.value.filter((e) => e.type === "AUDIT").length
  const denied = events.value.filter(
    (e) => e.type === "POLICE" && e.reason !== "unknown"
  ).length
  return { total, police, audit, denied }
})

const formatTime = (tsMs) => {
  if (!tsMs) return "--:--:--"
  const d = new Date(tsMs)
  return d.toLocaleTimeString("pt-BR", { hour12: false })
}

const formatRelative = (tsMs) => {
  if (!tsMs) return ""
  const now = Date.now()
  const diff = now - tsMs
  if (diff < 1000) return "agora"
  if (diff < 60000) return `${Math.floor(diff / 1000)}s atrás`
  if (diff < 3600000) return `${Math.floor(diff / 60000)}min atrás`
  return formatTime(tsMs)
}

const clearEvents = () => {
  events.value = []
}

const reconnectNow = () => {
  if (ws.value) {
    ws.value.close()
  }
  connectWebSocket()
}

onMounted(() => {
  console.log("[frontend] Mounted, starting WebSocket connection")
  connectWebSocket()
  fetchDenied()
  fetchCgroupProcs()
  startCgProcsPoll()
})

onUnmounted(() => {
  if (ws.value) ws.value.close()
  if (reconnectInterval.value) clearInterval(reconnectInterval.value)
  stopCgProcsPoll()
})
</script>

<template>
  <div class="min-h-screen p-4">
    <!-- Debug banner -->
    <div class="mb-4 p-3 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-300">
      <div class="flex items-center gap-2 mb-1">
        <span class="w-2 h-2 rounded-full" :class="connected ? 'bg-green-500' : 'bg-red-500 animate-pulse'"></span>
        <span>{{ connected ? 'WebSocket CONECTADO' : 'WebSocket DESCONECTADO' }}</span>
        <span v-if="wsError" class="text-red-400">{{ wsError }}</span>
        <span class="text-slate-500">· {{ messageCount }} mensagens recebidas</span>
        <span v-if="lastReceived" class="text-slate-500">· último: {{ lastReceived }}</span>
      </div>
      <div class="flex gap-2">
        <button @click="reconnectNow" class="bg-slate-700 hover:bg-slate-600 text-white px-3 py-1 rounded text-sm">
          Reconectar
        </button>
        <button @click="clearEvents" class="bg-red-900/50 hover:bg-red-900 text-red-400 border border-red-900 px-3 py-1 rounded text-sm">
          Limpar eventos
        </button>
      </div>
    </div>

    <!-- Header -->
    <header class="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2">
          <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
          </svg>
          libbpf-exp Monitor
        </h1>
        <p class="text-slate-400 text-sm">
          eBPF process monitoring and policing — real-time event stream
        </p>
      </div>
    </header>

    <!-- Stats -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
        <div class="text-slate-400 text-xs uppercase font-semibold mb-1">Total</div>
        <div class="text-2xl font-bold text-white">{{ stats.total }}</div>
      </div>
      <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
        <div class="text-slate-400 text-xs uppercase font-semibold mb-1">Polícia LSM</div>
        <div class="text-2xl font-bold text-blue-400">{{ stats.police }}</div>
      </div>
      <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
        <div class="text-slate-400 text-xs uppercase font-semibold mb-1">Auditoria</div>
        <div class="text-2xl font-bold text-purple-400">{{ stats.audit }}</div>
      </div>
      <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
        <div class="text-slate-400 text-xs uppercase font-semibold mb-1">Negados</div>
        <div class="text-2xl font-bold text-red-400">{{ stats.denied }}</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 mb-6">
      <div class="flex flex-col sm:flex-row sm:items-center gap-4">
        <div class="flex items-center gap-2">
          <label class="text-xs text-slate-400">Tipo</label>
          <select
            v-model="filterType"
            class="bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="all">Todos</option>
            <option value="POLICE">Polícia (LSM)</option>
            <option value="AUDIT">Auditor</option>
          </select>
        </div>
        <div class="flex items-center gap-2">
          <label class="text-xs text-slate-400">Motivo</label>
          <select
            v-model="filterReason"
            class="bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="all">Todos</option>
            <option value="cgroup">Cgroup</option>
            <option value="inode">Inode</option>
            <option value="unknown">Desconhecido</option>
          </select>
        </div>
        <div class="flex-1 relative">
          <label class="text-xs text-slate-400">Buscar</label>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="PID, comm, cmd, cgroup..."
            class="w-full bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>
    </div>

    <!-- Active cgroup being policed -->
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 mb-6">
      <div class="flex items-center gap-2 mb-3">
        <span class="text-xs font-bold text-slate-400 uppercase">Cgroup sendo policiado</span>
        <span class="text-xs font-mono text-slate-300 bg-slate-900/50 px-2 py-1 rounded border border-slate-700">
          {{ activeCgroup }}
        </span>
        <span class="text-xs text-slate-500">O BPF nega chamadas bpf() para processos neste cgroup</span>
      </div>
      <div class="text-xs text-slate-500">
        O caminho /sys/fs/cgroup/denied é criado automaticamente pelo auditor se não existir. Use
        "Negar caminho" abaixo para adicionar mais cgroups à lista de negação.
      </div>
    </div>

    <!-- Command panel: deny/allow path via the middleman -->
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 mb-6">
      <div class="flex items-center gap-2 mb-3">
        <span class="text-xs font-bold text-slate-400 uppercase">Policiamento via Web</span>
      </div>
      <form @submit.prevent="sendCommand" class="flex flex-col sm:flex-row gap-4 items-end">
        <div class="flex items-center gap-2">
          <label class="text-xs text-slate-400">Ação</label>
          <select
            v-model="cmdAction"
            class="bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="deny_path">Negar caminho</option>
            <option value="allow_path">Permitir caminho</option>
          </select>
        </div>
        <div class="flex items-center gap-2">
          <label class="text-xs text-slate-400">Valor</label>
          <input
            v-model="cmdValue"
            type="text"
            placeholder="Caminho do cgroup (ex: /sys/fs/cgroup/denied)"
            class="bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
            @keyup.enter="sendCommand"
          />
        </div>
        <button
          type="submit"
          :disabled="cmdSubmitting"
          class="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 text-white px-4 py-1.5 rounded text-sm font-medium disabled:opacity-50"
        >
          {{ cmdSubmitting ? 'Enviando...' : 'Enviar' }}
        </button>
      </form>

      <!-- Command result -->
      <div v-if="cmdResult" class="mt-3 p-3 rounded text-sm font-mono"
           :class="cmdResult.ok ? 'bg-green-900/20 border border-green-700 text-green-300' : 'bg-red-900/20 border border-red-700 text-red-300'">
        <div class="flex justify-between mb-1">
          <span>{{ cmdResult.sent ? JSON.stringify(cmdResult.sent) : '—' }}</span>
          <span @click="clearCmdResult" class="cursor-pointer hover:underline">×</span>
        </div>
        <div>{{ cmdResult.message }}</div>
      </div>
    </div>

    <!-- Denied cgroup paths: currently denied paths and their resolved inodes -->
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 mb-6">
      <div class="flex items-center justify-between gap-2 mb-3">
        <span class="text-xs font-bold text-slate-400 uppercase">Caminhos negados</span>
        <span class="text-xs text-slate-500">{{ deniedCgroups.length }} entrada(s)</span>
      </div>
      <div v-if="deniedLoading" class="text-xs text-yellow-500 animate-pulse">carregando...</div>
      <div v-else-if="deniedCgroups.length === 0" class="text-slate-500 text-sm italic">
        Nenhum caminho negado no momento.
      </div>
      <div v-else class="max-h-48 overflow-y-auto border border-slate-700/50 rounded bg-slate-900/30">
        <div
          v-for="(entry, i) in deniedCgroups"
          :key="entry.path + '-' + i"
          class="flex items-center justify-between px-3 py-2 border-b border-slate-700/50 last:border-0"
        >
          <div class="flex items-center gap-2">
            <span class="text-xs font-mono text-slate-300">{{ entry.path }}</span>
            <span v-if="entry.inode !== undefined" class="text-xs text-slate-500 font-mono">
              (inode {{ entry.inode }})
            </span>
          </div>
          <button
            @click="allowPath(entry.path)"
            class="text-xs text-red-400 hover:text-red-300 underline"
            :title="`Permitir ${entry.path}`"
          >
            Permitir
          </button>
        </div>
      </div>
      <div class="mt-2 text-[10px] text-slate-500">
        Cada linha mostra um caminho de cgroup negado. O inode é resolvido
        automaticamente pelo servidor (o BPF nega com base no número do
        inode, não no caminho). Clique em "Permitir" para remover da lista
        de negação.
      </div>
    </div>

    <!-- PID deny/allow panel: deny or allow individual PIDs.
         Works without writing to cgroup.procs (broken under WSL2). -->
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 mb-6">
      <div class="flex items-center gap-2 mb-3">
        <span class="text-xs font-bold text-slate-400 uppercase">Negar/permitir PID (BPF)</span>
        <span class="text-xs text-slate-500">sem cgroup.procs</span>
      </div>
      <form @submit.prevent="denyPid" class="flex flex-col sm:flex-row gap-4 items-end">
        <div class="flex items-center gap-2">
          <label class="text-xs text-slate-400">PID</label>
          <input
            v-model="pidDenyValue"
            type="text"
            inputmode="numeric"
            placeholder="PID do processo"
            class="bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
            @keyup.enter="denyPid"
          />
        </div>
        <button
          type="submit"
          :disabled="pidDenySubmitting"
          class="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 text-white px-4 py-1.5 rounded text-sm font-medium disabled:opacity-50"
        >
          {{ pidDenySubmitting ? 'Enviando...' : 'Negar PID' }}
        </button>
      </form>

      <!-- PID deny/allow result -->
      <div v-if="pidDenyResult" class="mt-3 p-3 rounded text-sm font-mono"
           :class="pidDenyResult.ok ? 'bg-green-900/20 border border-green-700 text-green-300' : 'bg-red-900/20 border border-red-700 text-red-300'">
        <div class="flex justify-between mb-1">
          <span>{{ pidDenyResult.sent ? JSON.stringify(pidDenyResult.sent) : '—' }}</span>
          <span @click="pidDenyResult = null" class="cursor-pointer hover:underline">×</span>
        </div>
        <div>{{ pidDenyResult.message }}</div>
      </div>
    </div>

    <!-- cgroup.procs: PIDs currently inside the denied cgroup (read only) -->
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 mb-6">
      <div class="flex items-center justify-between gap-2 mb-3">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-slate-400 uppercase">Processos no cgroup negado (cgroup.procs)</span>
          <span class="text-xs text-slate-500">{{ cgProcsCgroup }}</span>
        </div>
        <div class="flex items-center gap-2">
          <span v-if="cgProcsLoading" class="text-xs text-yellow-500 animate-pulse">carregando...</span>
          <button
            v-else
            @click="fetchCgroupProcs"
            class="text-xs text-blue-400 hover:text-blue-300 underline"
          >
            Atualizar
          </button>
        </div>
      </div>
      <div v-if="cgProcsError" class="mb-3 p-2 rounded bg-red-900/30 border border-red-800 text-red-300 text-xs">
        {{ cgProcsError }}
      </div>
      <div v-else-if="cgProcsPids.length === 0" class="text-slate-500 text-sm italic">
        Nenhum processo no cgroup negado no momento (ou cgroup.procs não acessível).
      </div>
      <div v-else class="max-h-48 overflow-y-auto border border-slate-700/50 rounded bg-slate-900/30">
        <div
          v-for="(pid, i) in cgProcsPids"
          :key="pid + '-' + i"
          class="flex items-center justify-between px-3 py-2 border-b border-slate-700/50 last:border-0"
        >
          <span class="text-xs font-mono text-slate-300">{{ pid }}</span>
          <span class="text-xs text-slate-500">em cgroup.procs</span>
          <button
            :disabled="cgRemoveSubmitting || cgRemovePid === pid"
            @click="removeFromCgroup(pid, cgProcsCgroup)"
            class="text-xs text-red-400 hover:text-red-300 underline disabled:text-slate-600 disabled:cursor-not-allowed"
            :title="cgRemovePid === pid ? 'Removendo do cgroup...' : 'Remover do cgroup'"
          >
            {{ cgRemovePid === pid ? 'Removendo...' : 'Remover' }}
          </button>
        </div>
      </div>
      <div class="mt-2 text-[10px] text-slate-500">
        Cada linha mostra um PID listado em cgroup.procs do cgroup negado.
        Clique "Remover" para mover esse PID para o cgroup pai (saída do
        cgroup negado). Isso escreve em cgroup.procs; sob WSL2 pode falhar
        com EBUSY — o servidor tenta até 10 vezes com backoff. Se não der,
        escreva manualmente: echo PID > /sys/fs/cgroup/cgroup.procs.
        Atualiza a cada 3s automaticamente.
      </div>
    </div>

    <!-- Event Table -->
    <div class="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
      <table class="w-full text-left">
        <thead>
          <tr class="bg-slate-900/50 border-b border-slate-700">
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Hora</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Tipo</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">PID</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Comando</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Cgroup ID</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Inode</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Cmd / Ação</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Motivo</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Retorno</th>
            <th class="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Nome</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-700/50">
          <tr
            v-for="e in filteredEvents"
            :key="e.id"
            class="hover:bg-slate-700/30 transition-colors border-l-4"
            :class="[
              e.type === 'POLICE' ? 'bg-red-500/10 border-red-500' : 'bg-blue-500/10 border-blue-500',
              e.reason === 'cgroup' ? 'border-red-500' :
              e.reason === 'inode' ? 'border-orange-500' : 'border-slate-500',
            ]"
          >
            <td class="px-4 py-3 text-sm text-slate-300 font-mono">
              {{ formatRelative(e.ts_ms) }}
              <br />
              <span class="text-xs text-slate-500">{{ formatTime(e.ts_ms) }}</span>
            </td>
            <td class="px-4 py-3 text-sm font-mono">
              <span
                class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-bold"
                :class="
                  e.type === 'POLICE'
                    ? 'bg-blue-900/30 text-blue-400 border border-blue-500/30'
                    : 'bg-purple-900/30 text-purple-400 border border-purple-500/30'
                "
              >
                {{ e.type === 'POLICE' ? 'POLICE' : 'AUDIT' }}
              </span>
            </td>
            <td class="px-4 py-3 text-sm text-white font-mono">{{ e.pid }}</td>
            <td class="px-4 py-3 text-sm text-white font-mono truncate max-w-[120px]">{{ e.comm }}</td>
            <td class="px-4 py-3 text-sm text-slate-300 font-mono">{{ e.cgid }}</td>
            <td class="px-4 py-3 text-sm text-slate-300 font-mono">{{ e.inode }}</td>
            <td class="px-4 py-3 text-sm text-white font-mono">
              {{ e.type === 'POLICE' ? ('#' + e.cmd) : e.cmd_str }}
            </td>
            <td class="px-4 py-3 text-sm font-mono capitalize">{{ e.reason }}</td>
            <td class="px-4 py-3 text-sm text-slate-300 font-mono">
              {{ e.ret !== undefined ? e.ret : '—' }}
            </td>
            <td class="px-4 py-3 text-sm text-slate-300 font-mono truncate max-w-[100px]">
              {{ e.name || '—' }}
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="filteredEvents.length === 0" class="p-8 text-center text-slate-500">
        <p v-if="!connected">WebSocket não conectado. Verifique se o middleman está rodando na porta 8000.</p>
        <p v-else-if="events.length > 0">Todos os eventos foram filtrados. Ajuste os filtros acima.</p>
        <p v-else>Nenhum evento recebido. Aguardando dados do eBPF auditor...</p>
      </div>
    </div>

    <!-- Raw messages debug panel -->
    <div v-if="rawMessages.length > 0" class="mt-6 bg-slate-900/50 rounded border border-slate-700/50 p-4 overflow-hidden">
      <div class="flex items-center gap-2 mb-2">
        <span class="text-xs font-bold text-slate-400 uppercase">Mensagens brutas recebidas (últimas {{ rawMessages.length }})</span>
      </div>
      <div class="overflow-x-auto font-mono text-xs text-slate-300">
        <div v-for="(m, i) in rawMessages" :key="i" class="mb-1 truncate">
          <span class="text-slate-500">{{ m.time }}</span> {{ JSON.stringify(m.data) }}
        </div>
      </div>
    </div>

    <!-- Footer -->
    <footer class="mt-8 text-slate-500 text-xs text-center">
      libbpf-exp — eBPF Process Monitor &amp; Policing Tool
    </footer>
  </div>
</template>

<style>
body {
  font-family: "Inter", sans-serif;
  background-color: #0f172a;
  color: #e2e8f0;
}
.font-mono {
  font-family: "JetBrains Mono", monospace;
}
</style>
