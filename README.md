# libbpf-exp

Ferramenta de monitoramento e policiamento de processos baseada em eBPF para Linux.
Intercepta chamadas ao sistema `bpf()` e eventos de execução (`exec`) por meio de
programas BPF tipo LSM e kprobe/tracepoint, aplica políticas de negação baseadas
em cgroups (`-EPERM`) ou modo apenas auditoria, e expõe os eventos em tempo real
para um painel web (Vue 3) através de uma ponte FastAPI (middleman) sobre WebSocket.

```text
┌─────────────────────────────────────────────────────────────────────┐
│  eBPF Auditor (C)                                                   │
│  ┌─────────────┐    ring buffer   ┌──────────────┐  (kernel)       │
│  │ police.bpf  │ ◄───────────────►│ auditor.bpf  │                 │
│  │ (lsm/bpf)   │                  │ (kprobe+)    │                 │
│  └──────┬──────┘                  └──────┬───────┘                 │
│         │ JSON sobre soquete UNIX        │                         │
│         ▼                                ▼                         │
│   struct monitor              FastAPI Middleman                   │
│   socket.c        ◄───────────────► main.py                       │
│   (userspace)     /tmp/libbpf-exp.sock   WebSocket /ws            │
│                      │                      │                      │
│                      │                    ┌─┴─┐                    │
│                      │                    │ Vue 3 │                │
│                      │                    │Frontend│               │
│                      │                    └─┬─┘                    │
│                      │                      ▼                      │
│                      │              http://localhost:5173          │
└─────────────────────────────────────────────────────────────────────┘
```

## Componentes

| Componente | Linguagem | Função |
|------------|-----------|--------|
| `police` (LSM BPF) | C + BPF | Anexa ao hook `lsm/bpf`, intercepta `bpf()`, nega ou registra com base na lista negra de cgroups/inodes |
| `auditor` (kprobe + tracepoint) | C + BPF | Rastreia `bpf()` e eventos `exec` via kprobes e tracepoints |
| `auditor` (userspace) | C | Carrega e anexa programas BPF, consome ring buffers, exporta eventos via soquete UNIX |
| `monitor socket` | C (`socket.c`) | Exporta eventos do ring buffer como JSON delimitado por nova linha através de soquete UNIX |
| `middleman` | Python / FastAPI | Recebe JSON do soquete do auditor e transmite para clientes frontend via WebSocket; persiste histórico em disco |
| `frontend` | Vue 3 | Painel em tempo real com estatísticas, filtros, tabela de eventos e histórico persistente |

## Estrutura de diretórios (refatorada)

```
libbpf-exp/
├── CMakeLists.txt            # Sistema de compilação C
├── README.md                 # Este documento
├── LICENSE                   # Licença BSD-3-Clause
├── src/                      # Código-fonte C (eBPF auditor)
│   ├── userspace/            # Espaço do usuário: main.c, police.c, auditor.c, socket.c + cabeçalhos
│   └── bpf/                  # Programas BPF: police.bpf.c, auditor.bpf.c + cabeçalhos
├── include/                  # Cabeçalhos públicos + gerados (vmlinux.h, .skel.h)
├── middleman/                # Ponte FastAPI (Python)
│   ├── main.py
│   ├── test_main.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                 # Interface Vue 3
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.js
│       └── App.vue
├── tests/                    # Suíte de testes (Python)
│   ├── test_*.py
│   └── test_vite.sh
├── scripts/                  # Scripts Shell
│   ├── start.sh              # Suíte de testes de integração
│   ├── start-monitor.sh      # Inicia auditor + middleman + frontend
│   ├── start-stack.sh
│   ├── check_stack.sh
│   ├── restart_middleman.sh
│   ├── setup-frontend.sh
│   └── setup-wsl.sh
├── docker/                   # Imagens e orquestração (opcional)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── dockerbuild.sh
├── docs/                     # Documentação (LaTeX, modelo SBC)
│   ├── libbpf-exp.tex
│   ├── libbpf-exp.pdf
│   └── README.md
├── build/                    # Saída de compilação CMake
├── gen/                      # Objetos BPF gerados
└── docs/                     # Documentação (LaTeX, modelo SBC)
    ├── libbpf-exp.tex
    ├── libbpf-exp.pdf
    └── README.md

O arquivo `sbc-latex-template-master.zip` (template de estilo da SBC) está
na raiz do repositório e deve ser extraído dentro de `docs/` antes de
compilar o documento LaTeX.
```

## Pré-requisitos

### Sistema (kernel Linux)

- Kernel Linux com **cgroup v2** montado em `/sys/fs/cgroup`
- Kernel com LSM **`bpf`** habilitado (`lsm=bpf` ou `lsm=landlock,bpf,...`)
- **BTF habilitado** (`CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DEBUG_INFO_BTF_MODULES=y`)
- `/sys/kernel/btf/vmlinux` acessível (para geração de `vmlinux.h` via `bpftool`)
- Privilégios de root (para anexação de programas BPF LSM e gerenciamento de cgroups)

### Dependências de compilação (auditor eBPF)

- `cmake` (≥ 3.18)
- `clang` / `llvm` (compilação para alvo BPF)
- `libbpf-dev` (biblioteca userspace eBPF)
- `bpftool` (geração de `vmlinux.h` e inspeção BPF)
- `make`, `libelf-dev`, `libz-dev`, `pkg-config`

### Dependências do middleman (frontend)

- Python 3 + `fastapi` + `uvicorn`
- (Opcional) Node.js + `npm` para o servidor de desenvolvimento Vue

## Início rápido (sem Docker)

### 1. Compilar o auditor eBPF

```bash
cd ~/libbpf-exp
cmake -S . -B build
cmake --build build
```

Isso produz `build/auditor` e gera automaticamente `include/vmlinux.h` a partir do BTF do kernel via `bpftool`.

### 2. Verificar BTF

```bash
ls -la /sys/kernel/btf/vmlinux
bpftool feature | grep -iE 'DEBUG_INFO_BTF|CONFIG_BPF'
```

### 3. Iniciar o middleman FastAPI

```bash
cd ~/libbpf-exp/middleman
python3 -m pip install -r requirements.txt
python3 main.py
```

O middleman expõe:
- API HTTP em `http://localhost:8000`
- Health check em `http://localhost:8000/health`
- Histórico e clientes em `http://localhost:8000/v1/models`
- Lista de negados em `http://localhost:8000/v1/denied`
- WebSocket em `ws://localhost:8000/ws`
- Ouvinte de soquete UNIX em `/tmp/libbpf-exp.sock`

O histórico de eventos é persistido em `/tmp/libbpf-exp-events.json`, sobrevivendo a reinicializações do middleman e a recargas da página do frontend.
A lista de cgroups e inodes negados é persistida em `/tmp/libbpf-exp-denied.json`, sobrevivendo a reinicializações do middleman.

### 4. Iniciar o auditor eBPF (requer root)

```bash
cd ~/libbpf-exp
sudo mkdir -p /sys/fs/cgroup/denied
sudo build/auditor /sys/fs/cgroup/denied
```

### 5. Abrir o frontend

Abra `frontend/index.html` diretamente no navegador. Ele se conecta a `ws://localhost:8000/ws` — nenhuma etapa de compilação é necessária.

Ou, com o servidor de desenvolvimento Vue:

```bash
cd ~/libbpf-exp/frontend
npm install
npm run dev        # serve em http://localhost:5173
```

### 6. Executar a suíte de testes de integração

```bash
sudo ./scripts/start.sh
```

A suíte valida: negação de subárvore, correspondência exata, modo auditoria, restauração de acesso e emissão de eventos de auditoria. Requer root, cgroup v2, LSM `bpf`, `bpftool` e `/sys/fs/bpf` montado.

### 7. Executar os testes unitários do middleman (Python)

Os testes de API HTTP/WebSocket do middleman FastAPI usam `pytest` e `httpx`. Não exigem root, kernel eBPF, cgroups ou um servidor rodando — usam o `TestClient` do FastAPI com um soquete de auditor simulado.

```bash
cd ~/libbpf-exp/tests
pip install -r requirements.txt
pytest -v
```

Os testes cobrem: endpoints de saúde/info (`/health`, `/`, `/openapi.json`, `/v1/models`), comando de negação/permissão por inode e caminho (`/v1/command`), comportamento sem auditor conectado, mover processo para cgroup (`/v1/cgroup/move`), conexão WebSocket e backfill de histórico persistido.

### Script tudo-em-um (monitor)

```bash
sudo ./scripts/start-monitor.sh [--no-frontend]
```

Inicia o middleman, o auditor e, opcionalmente, o servidor de desenvolvimento Vue.

## Arquitetura de dados

O auditor emite eventos como JSON (uma linha por evento) através de um soquete UNIX. O middleman lê esse soquete, valida cada linha, transmite via WebSocket a todos os clientes conectados e persiste o histórico em disco. O frontend consome o WebSocket e renderiza estatísticas, filtros e a tabela de eventos.

Exemplo de evento POLICE:
```json
{"ts_ms":1731500000000,"type":"POLICE","pid":1234,"comm":"bpftool",
 "cgid":5678,"inode":5678,"cmd":5,"reason":"cgroup"}
```

Exemplo de evento AUDIT:
```json
{"ts_ms":1731500000001,"type":"AUDIT","pid":1234,"comm":"bpftool",
 "cgid":5678,"inode":5678,"cmd":1,"cmd_str":"BPF_PROG_LOAD",
 "type":1,"key_size":4,"value_size":4,"max_entries":8,"ret":0,"name":"prog"}
```

## Persistência

O histórico de eventos recente (últimos 100) é gravado em `/tmp/libbpf-exp-events.json` sempre que um novo evento chega. Ao iniciar, o middleman carrega esse arquivo se existir. Quando um cliente frontend se conecta (incluindo após recarregar a página), o middleman envia o histórico acumulado, de modo que os logs não desaparecem com recargas ou reinicializações do servidor.

## Documentação acadêmica

A documentação detalhada da experiência (em português brasileiro, modelo SBC/LaTeX) encontra-se em `docs/libbpf-exp.tex`, com as seções: Introdução, Contexto, Experimento e Conclusão.

## Licença

BSD-3-Clause (veja `LICENSE`).
