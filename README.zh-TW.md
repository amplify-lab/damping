# Damping

[English](README.md) | **繁體中文**

**一套政策，一份稽核紀錄，同時涵蓋你的終端機與 MCP 伺服器。**

Damping 介於你的 AI 編碼代理人（Claude Code、Cursor、Codex，未來會支援更多）與真實世界之間。在一個具破壞性的 shell 指令、或一次高風險的 MCP 工具呼叫真正執行之前，Damping 會先拿它去對照政策引擎，讓你有機會說不——不論最後是放行還是擋下，都會記錄下來，統一放在同一個地方，不管這個動作是從哪個管道發起的。

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete of a path that isn't a known regenerable build/cache directory (node_modules, dist, build, ...) — for your home directory, filesystem root, or a configured protected path, this could destroy irreplaceable data

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

## 阻尼，簡單說

*Damping*（阻尼）在物理學裡，是抑制系統暴衝式振盪、把系統拉回穩定範圍的那股力——它不是讓系統停下來，而是讓它穩定下來。這正是整個產品理念：**治理不是要把你的 AI agent 綁死，而是要「阻尼」它的失效模式，讓它能穩定運作。**（屬於 Amplify Lab 物理主題產品家族的一員。）

## 快速開始

### 1. 安裝與設定

```
curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | sh
damping init                # 偵測 Claude Code / Cursor / Codex，安裝預設政策，註冊 hook
```

Homebrew 現在也能用了——`brew install amplify-lab/tap/damping`（這是自訂 tap，不是 `homebrew-core`，所以一定要加上 `amplify-lab/tap` 這個前綴；單純打 `brew install damping` 永遠不會裝到這個 cask）。`curl -sSL https://damping.dev/install | sh` 這個還沒上線——下面「部署 Damping」那節有講具體還缺什麼。以上三種方式裝的都是同一份、經過 checksum 驗證的真實二進位檔，來自同一個 GitHub Release。

`damping init` 執行完會針對每一個偵測到並成功接上的 agent 印出確認訊息，最後會附上一行 demo 建議（`ask your agent to run rm -rf /tmp/test`）——這就是下面第 2 步。

### 2. 看它實際攔一次

叫你的 agent（Claude Code、Cursor、Codex）跑一個 Damping 預設政策會判定為破壞性的指令——用 `rm -rf /tmp/test` 是最安全的示範方式，不會動到真實資料。你會在自己的終端機看到這個畫面，不是在 agent 自己的對話視窗裡（Damping 有自己獨立的確認提示，走 `/dev/tty`，不受觸發它的 agent 影響）：

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete of a path that isn't a known regenerable build/cache directory (node_modules, dist, build, ...) — for your home directory, filesystem root, or a configured protected path, this could destroy irreplaceable data

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

- **`a`** / **`d`**：只決定這一次要不要放行。
- **`A`** / **`D`**：把這個決定記住（寫成一條精確比對的規則，存進你的政策檔），同一個指令以後就不會再問了——確認過你工作流程裡某個重複出現的指令（例如 build script 裡的 `rm -rf ./dist/*`）其實沒問題之後，這個選項就很好用。

### 3. 回顧發生過什麼事

不論放行、詢問還是擋下，也不論走哪個管道，Damping 評估過的每一個動作都會進到同一份稽核紀錄裡：

```
damping log                        # 重播它攔過的所有事件，跨所有管道
damping log --risk critical        # 只看嚴重程度 critical 的事件
damping log --channel mcp --since 24h
damping log --follow               # 像 tail -f 一樣即時追蹤
```

或是用本機、免設定的網頁介面打開同一份紀錄：

```
damping dashboard                  # 預設綁定 127.0.0.1:4243
```

<img src="docs/assets/dashboard-demo.png" alt="damping dashboard showing a filterable event table with per-session risk sparklines, mixing CLI and MCP channel events across all four risk tiers" width="700">

*（這是用一份灌好種子資料的本機稽核紀錄產生的真實畫面，不是示意圖。裡面同時有兩種管道、四種風險等級、allow/deny/prompt 三種結果、兩個不同的 agent——這正是重點所在：一張表，不是每個工具各自一張。）*

### 4. 順便把你的 MCP 伺服器也罩住

把你的 MCP client 設定指向 Damping，而不是直接指向真正的伺服器：

```
damping mcp wrap -- npx @some-org/example-mcp-server
```

Damping 會探測真實伺服器提供的工具、原封不動重新暴露出來，並讓每一次呼叫都先走過跟你終端機一模一樣的政策引擎與稽核紀錄，才轉送出去。從 client 的角度看，被包裝過的伺服器行為完全沒變，唯一差別是：一次具破壞性的工具呼叫現在也能被攔下來，就跟攔一個 shell 指令一樣。

### 5. 平常會用到的指令

```
damping status                     # 目前是否啟用、用哪個政策、接了哪些 agent
damping doctor                     # 健康檢查——hook 有沒有註冊、政策檔是否有效、有沒有降級模式紀錄
damping policy test "rm -rf ~/"     # 拿一個指令乾跑一次政策比對，不會有任何副作用
damping off --for 30m               # 暫停執行（唯一被支援的停用方式——原因見 docs/threat-model.md §4）
```

完整指令參考：[`docs/cli-reference.md`](docs/cli-reference.md)。

## 部署 Damping

**各種安裝方式目前的真實狀態**——直接對照現有的正式發布版本查證過，不是憑印象寫的：

| 方式 | 狀態 |
| --- | --- |
| `curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh \| sh` | **現在就能用**——會下載對應平台的壓縮檔（來自最新的 GitHub Release）、驗證 SHA-256 checksum、安裝到 `/usr/local/bin`（可用 `DAMPING_INSTALL_DIR` 覆寫安裝路徑；用 `DAMPING_VERSION=vX.Y.Z` 指定版本） |
| 從 [GitHub Releases](https://github.com/amplify-lab/damping/releases) 手動下載 | **現在就能用**——每個版本都有 5 種平台的壓縮檔（linux/darwin × amd64/arm64，windows/amd64）加上 `checksums.txt` |
| `brew install amplify-lab/tap/damping` | **現在就能用**（`v0.2.1` 起）——`amplify-lab/homebrew-tap` 是自訂 tap，不是 `homebrew-core`，一定要加 `amplify-lab/tap` 這個前綴；單純 `brew install damping` 永遠裝不到這個 cask |
| `curl -sSL https://damping.dev/install \| sh` | **還沒上線**——`damping.dev` 已經註冊，但這個路徑還沒設定成提供 `install.sh` 的內容 |

**更新**：目前還沒有 `damping update`/`damping upgrade` 這種子指令——重新跑一次當初用的安裝方式就好（`curl ... | sh` 或 `brew upgrade amplify-lab/tap/damping`），會自動抓最新版本。有一件事升級**不會**幫你做：`damping init` 絕對不會覆蓋已經存在的 `~/.damping/policy.yaml`，這是刻意設計的，為的是不要蓋掉你自己加的 `always_allow`/`always_deny`/`protected_paths` 客製化設定——這也代表新版 binary 內建的額外規則，不會自動加進一台已經有政策檔的機器裡。`damping doctor` 會檢查你的政策檔是否缺少目前這個版本內建的規則並提出警告；用 `damping init --force` 可以刷新成目前的最新預設值（這會整個覆蓋檔案，記得事後把自己的客製化設定補回去）。

**部署給整個團隊，而不只是自己**：V1 目前沒有集中式的機隊管理或推送式部署機制——每個開發者都得自己在自己的機器上跑 `damping init`，每一台機器的 `~/.damping/policy.yaml` 彼此獨立、互不相干。如果你現在就想讓整個團隊套用同一份政策，比較實際的做法是自己散布 `policy.yaml`（例如透過你自己的 dotfiles repo，或是寫一個 wrapper script 在 `damping init` 之後把檔案複製過去），而不是依賴 Damping 內建的任何機制——集中式的政策分發跟機隊管理是 Phase 5 的範圍，現在還沒做。

**確認某次部署真的成功了**，在任何一台機器上：

```
damping doctor      # hook 註冊狀態、政策是否有效、降級模式歷史紀錄——只要有問題就會回傳 exit code 4
damping status      # 現在是否為 ON、用的是哪個政策檔、實際接上了哪些 agent
```

兩個指令都是唯讀、可以重複安全執行——`damping doctor` 是這裡面唯一「失敗時會回傳非 0 exit code」的指令，適合寫進 onboarding checklist 或健康檢查腳本裡。但除了「有沒有裝好」之外，真正能證明它「有在運作」的方式還是上面第 2 步的 demo：叫 agent 跑 `rm -rf /tmp/test`，親眼確認真的跳出攔截提示，而不是只確認 `$PATH` 上找得到這個執行檔。

**暫停或移除**：`damping off`（可加 `--for 30m`）是官方支援的暫時停用方式——為什麼不是直接刪掉執行檔，原因見 `docs/threat-model.md` §4。如果要完全移除 Damping：刪掉安裝的執行檔、刪掉 `~/.damping/`、並把 `damping init` 加進 `~/.claude/settings.json` / `~/.cursor/hooks.json` / `~/.codex/hooks.json` 裡的 hook 項目移除（移除之後 `damping doctor` 會回報該 hook 已經不存在，可以拿來確認真的移除乾淨了）。

## 為什麼不乾脆用 dcg、Aegis 或 Pipelock 就好？

老實說，如果你要的只是「擋掉 `rm -rf`」，[dcg](https://github.com/Dicklesworthstone/destructive_command_guard) 已經很成熟、很多人在用、也做得不錯——你應該考慮它。Damping 真正的賭注不一樣：**同一套政策引擎、同一份稽核紀錄，也涵蓋你的 MCP 工具呼叫**，不只是終端機而已。當你的 agent 在任一邊觸發規則之後，跑一次 `damping log` 就會看到兩邊的事件都在同一份紀錄裡，還能依管道篩選：

```
$ damping log --channel cli
$ damping log --channel mcp
```

以下是跟這個領域裡最接近的幾個工具的老實比較——我們寧願誠實列出對方贏在哪裡，也不假裝他們沒有優勢（`docs/00-統一開發計畫（定案版）.md` §三 有這張表背後完整的研究依據）：

| | 贏在哪裡 | 做不到什麼 |
| --- | --- | --- |
| **[dcg](https://github.com/Dicklesworthstone/destructive_command_guard)** | 1,150+ 星、每天都有 commit、整合了 10 種以上的 agent（Claude Code、Codex、Gemini CLI、Copilot CLI、Cursor、Grok、Aider），內建規則庫也比 Damping 現在出貨的還多 | 只做 CLI——沒有 MCP 工具呼叫的涵蓋範圍，也沒有跨管道的稽核紀錄 |
| **[Aegis](https://github.com/Justin0504/Aegis)** | 這個領域裡最接近「一套政策 + 稽核 gateway」的 OSS 專案，有加密稽核紀錄跟人工核可機制，還支援 9 種以上框架的 SDK | 是一種以 gateway/SDK、以執行期中介點為核心的部署模式，不是輕量、per-agent 的 CLI+MCP hook——運作型態完全不同，對個人開發者的終端機來說不是能直接替換的選項 |
| **[Pipelock](https://github.com/luckyPipewrench/pipelock)** | 專門為 MCP/HTTP/A2A 流量打造的 AI agent 防火牆——外洩、SSRF、prompt injection 偵測，還有簽章過的行為收據 | 回答的是「資料有沒有外洩」，不是「這個特定動作到底做了什麼、是誰授權的」——沒有細粒度的 per-tool-call 授權機制，也沒有統一的稽核紀錄 |
| **Damping** | 同一套政策引擎、同一份稽核紀錄同時涵蓋終端機跟 MCP 伺服器，鎖定個人開發者規模，用真正的 AST 解析（`mvdan/sh`）而不是正規表達式，零遙測，單一靜態 Go 執行檔 | 四個裡面最新——內建規則庫比 dcg 小；沒有加密稽核紀錄，也沒有 gateway 部署模式（這是 Aegis 的強項） |

這個領域裡沒有其他人在個人開發者這個規模上，把 CLI 跟 MCP 統一在同一套引擎、同一份稽核紀錄底下——這才是真正的差異化,不只是「擋 shell 指令」這個 demo 而已。

## 這些真實事故是它要防的

下面每一條規則的存在，都是因為有一個真實、有紀錄可查的事故，不是憑空想像的情境。Damping 的規則都有來源可查，也都拿事故當時真實的指令樣態測過，寫進這裡之前也都重新查證過一次。

| 發生了什麼事 | 攔下它的規則 |
| --- | --- |
| 一個 Claude Code session 跑了 `rm -rf`，把使用者整個家目錄清空了。 | `destructive.rm_rf_protected` |
| 一個 Cursor agent 在被明確告知「不要執行任何東西」之後，還是刪了 70 個檔案。 | `destructive.rm_rf_protected` |
| 一個 Replit agent 刪掉了一個正式資料庫，影響到某客戶公司 1,200 多位主管。 | `destructive.sql_drop_truncate`(現在也涵蓋沒有 `WHERE` 條件的 `UPDATE`/`DELETE`，以及 `redis-cli FLUSHALL`/`FLUSHDB`) |
| 一個跑在沙箱裡的 agent 透過 `/proc/self/root/usr/bin/npx` 繞過了黑名單，被抓到之後乾脆把整個沙箱關掉。 | `destructive.proc_sandbox_bypass` |
| 一個 Claude Code session 對 DataTalks.Club 真實的正式 AWS 帳號跑了 `terraform destroy`(換機器之後留下一份過期的 Terraform state 檔案)，把 VPC/RDS/ECS 整套架構都刪了——2.5 年的課程資料、約 194 萬筆資料庫紀錄，靠 AWS 主控台裡一份原本看不到的快照才救回來([Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/claude-code-deletes-developers-production-setup-including-its-database-and-snapshots-2-5-years-of-records-were-nuked-in-an-instant) 報導，收錄於 [incidentdatabase.ai](https://incidentdatabase.ai/cite/1424) 事故編號 #1424)。 | `destructive.iac_destroy` / `destructive.iac_apply_unreviewed`(同時也攔 `pulumi destroy`/`up --yes`、`cdk destroy`，以及任何跳過工具本身人工審查步驟的 `terraform apply`/`pulumi up`) |
| TrapDoor 攻擊行動(2026 年 5 月，經 [socket.dev 查證](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates))：在 `CLAUDE.md`/`.cursorrules` 檔案裡埋藏隱藏指示，誘導 Claude Code 跟 Cursor 執行一個假的「安全掃描」，藉機讀取並外洩 SSH 金鑰、AWS 憑證，以及 Solana/Sui/Aptos 加密貨幣錢包的 keystore。 | `destructive.secret_exfiltration`——這是一條通用的憑證外洩規則(任何受保護路徑被讀取、並送往未允許清單內的網路目的地都會觸發)，不是專門針對加密貨幣；錢包 keystore 路徑只是同一份清單裡多加的幾筆項目而已 |
| Anthropic 自家的 Claude Code，在近期一則 CHANGELOG 項目之後，原生就會擋下 `git reset --hard`/`clean -fd`/`stash drop`/`checkout -- .` 以及 `terraform`/`pulumi`/`cdk destroy`——但僅限 Claude Code 自己的「auto」模式、僅限這一家廠商，而且是靠模型自己的判斷，不是一條確定性規則。 | `destructive.git_history_destructive`、`destructive.iac_destroy`——不綁定特定工具，判斷方式也是確定性的，所以不管你用哪個 agent、哪個模式，防護都一樣 |
| CVE-2025-53773(GitHub Copilot)：一個 prompt injection payload 把 `chat.tools.autoApprove: true` 寫進 `.vscode/settings.json`——這是一次單純的檔案編輯，不是 shell 指令，結果之後每一個終端機指令都變成不用確認就直接執行。CVE-2026-50549(「DuneSlide」，Cursor，CVSS 9.8)：一次由 prompt injection 驅動的 symlink 寫入，逃出了 Cursor 自己的沙箱，並覆寫了它的沙箱輔助執行檔。這兩個都是純粹的檔案寫入攻擊，一個只看 shell 指令的攔截器根本看不到。 | `destructive.agent_permission_escalation`、`destructive.git_hook_write`、`destructive.npm_lifecycle_script_write`——Damping 現在也會攔截 Claude Code 的 `Write`/`Edit`/`MultiEdit` 工具呼叫，不只是 `Bash`。**目前僅限 Claude Code**——Cursor 沒有能夠攔截的 pre-write hook(所以就算有這個擴充，也擋不住 DuneSlide 這起事故)，Codex 的 `PreToolUse` 也完全不會為這幾個工具名稱觸發；詳見 [`docs/cli-reference.md`](docs/cli-reference.md) §11 |
| 一位 DevOps 工程師自己寫的事後檢討：在正式環境用 K9s 操作時，對錯的 namespace 下了 `kubectl delete`，讓正式環境的 ingress/負載平衡離線了大約 40 分鐘——接著 ArgoCD 的自動同步重新部署，又把 RabbitMQ 的 PersistentVolume 刪了，資料就這樣沒了([Gustavo Zanotto，2024 年 1 月](https://medium.com/@gustavo.zanotto/the-day-i-deleted-the-production-ingress-namespace-in-k8s-9ba4f56a7f05))。 | `destructive.kubectl_bulk_delete` |
| Amazon 自家「Amazon Q Developer」VS Code 擴充套件的一次被入侵的版本(v1.84，上線約 48 小時，2025 年 7 月)：內含一段被植入的 prompt，指示 AI agent——以 `--trust-all-tools --no-interactive` 方式呼叫——去尋找本機的 AWS profile，並執行 `aws ec2 terminate-instances`、`aws s3 rm`、`aws iam delete-user` 來清空使用者的雲端資源；AWS 已證實這次遭竄改並下架該版本([The Register](https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/))。 | `destructive.cloud_cli_mass_delete` |
| WhisperGate(威脅行為者 DEV-0586，後改名 Cadet Blizzard)，於 2022 年 1 月 13 日首次針對烏克蘭政府/組織系統發動：一款偽裝成勒索軟體的兩階段抹除工具，先覆寫 Master Boot Record，接著具破壞性地覆寫檔案內容，讓裝置完全無法使用且無實質復原手段可言([Microsoft MSTIC](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/))——這正是對整顆裝置下 `dd`/`shred`/`blkdiscard` 覆寫會重現的效果。 | `destructive.raw_device_write` |
| 2025 年 12 月 5 日，一名威脅行為者直接把惡意的 `finch-rust`(冒充正牌的 `finch` crate)跟 `sha-rust`(一個憑證外洩 payload)發布到 crates.io，crates.io 團隊當天就停用該帳號並刪除這兩個 crate([Rust Blog](https://blog.rust-lang.org/2025/12/05/crates.io-malicious-crates-finch-rust-and-sha-rust/))。 | `destructive.cargo_publish_unreviewed` |
| 2019 年 8 月，一名攻擊者入侵了某維護者的 RubyGems.org 帳號，藉此 gem-push 了四個惡意版本(1.6.10–1.6.13)的熱門 `rest-client` gem，其中 1.6.13 版含有憑證外洩兼挖礦後門——CVE-2019-15224([GitHub issue](https://github.com/rest-client/rest-client/issues/713))。 | `destructive.gem_push_unreviewed` |
| Socket 的威脅研究團隊記錄到 npm 套件 `mysql-dumpdiscord`(還有配套的 PyPI/RubyGems 套件)會讀取 `.env`/`config.json`/`ayarlar.json`，並把內容以 JSON 格式 POST 到一個寫死的 Discord incoming-webhook URL，這是一場把 Discord webhook 武器化、當作低成本、無需驗證的 C2/外洩基礎設施的更大規模行動的一部分，橫跨 npm、PyPI、RubyGems([Socket](https://socket.dev/blog/weaponizing-discord-for-command-and-control))。 | `destructive.webhook_exfiltration` |

特別針對加密貨幣/錢包操作說明：上面的憑證外洩路徑是真實存在、而且現在就直接針對 Claude Code/Cursor 的攻擊面(TrapDoor)。至於直接攔截錢包轉帳指令本身(`cast send`、`solana transfer` 等)則是範圍更窄、專屬 Web3 的情境，在這個產品面向上的證據還比較薄弱——列為未來可能新增的項目，現在還沒做，這裡也刻意不誇大。

**老實承認目前做不到，不假裝已經解決：** 有兩起真實的 2025-2026 供應鏈攻擊事件值得單獨點名，而不是硬塞進上面那張表裡，因為 Damping **目前還攔不到**這兩者——Nx/s1ngularity 攻擊(透過一個被武器化的 AI 編碼 agent，外洩了 2,349 組憑證，把偷來的機密推送到一個新建的公開 `gh repo create` repo 裡)以及 2026 年 5 月的 node-ipc 後門(透過 DNS TXT 查詢通道竊取憑證)。不管是 `gh repo create` 還是基於 DNS 的外洩手法，目前都不在 `destructive.secret_exfiltration` 的偵測範圍內——這兩個都是真實、範圍明確的未來規則候選，不是現在就已經涵蓋的東西。

## 現在真正做到了什麼(V1 / Phase 1)

以下每一項都已經實作完成，並且有通過的測試覆蓋——不是願景，是現況：

- CLI shell 指令攔截，採用真正的 AST 解析(不是正規表達式)，涵蓋 24 條預設規則(破壞性刪除、強制推送、破壞性 SQL/Mongo/Redis 操作、遞迴權限變更、未經查核的安裝 pipeline、編碼過的 payload、沙箱繞過路徑、infra-as-code 的 destroy/未審查 apply、破壞性的 git 歷史操作、憑證外洩、kubectl/雲端 CLI 大量刪除、對整顆區塊裝置的原始寫入、未審查的 crates.io/RubyGems 發布、聊天 webhook 外洩等等)——完整清單與每一條背後的真實事故，見 [`docs/threat-model.md`](docs/threat-model.md) 與上方「這些真實事故是它要防的」一節。
- Claude Code 的 `Write`/`Edit`/`MultiEdit` 工具呼叫，現在跟 `Bash` 受到一樣的對待——上面 24 條規則裡有 3 條專門攔截危險的*檔案寫入*(agent 權限升級、git-hook 持久化、npm 生命週期腳本注入)，不只是危險指令而已。目前僅限 Claude Code；Cursor 跟 Codex 為什麼還沒涵蓋，詳見 [`docs/cli-reference.md`](docs/cli-reference.md) §11。
- `damping mcp wrap`——同一套政策引擎、同一份稽核紀錄，也適用於 MCP 工具呼叫，不只是終端機。
- 本機的 `damping dashboard`(畫面如上)跟 `damping log`，可以重播跨兩種管道的完整稽核紀錄——附帶風險趨勢圖、觸發最多次規則的排行，以及時間區間/規則 ID 篩選器，這兩個圖表都是算在完整稽核歷史上，不只是畫面上看得到的那幾筆。
- 內建 OPA/Rego 政策引擎，作為預設 Go-native 引擎之外可選的替代方案。
- `damping compliance-report demo` / `export`——對最終企業版合規報表的一個早期、誠實揭露範圍的預覽版本：`demo` 不需要任何真實部署(完全用真實、已出貨的規則組成一份合成的 30 天資料集)，`export` 則是對你自己本機真實的稽核紀錄跑出同一份報表，支援 markdown/text/JSON/自帶圖表的 HTML 格式。明確聲明這不是完整的 Phase 5 企業版功能(沒有地端部署、沒有 AD/LDAP 身分綁定、沒有 PostgreSQL)——詳見 [`docs/cli-reference.md`](docs/cli-reference.md) §7.1。
- `noninteractive_prompt_fallback`——一個選擇性開啟的政策設定，讓一條 `prompt` 等級的規則在沒有終端機可以詢問人類時(例如一個無人看管、在背景執行的 agent)，改成依風險等級決定放行或擋下，取代原本無條件一律擋下的行為。
- 170 個 BDD(Gherkin)情境，全部都串接到真實程式碼並且通過，不只是寫在文件裡。
- 跨平台的發布工程(Homebrew、一行安裝腳本、涵蓋 linux/darwin × amd64/arm64 的 GitHub Releases)。

還沒做的：Phase 3 完整的企業版 Gateway(OAuth 2.1、confused-deputy 防護)、Phase 4 以 Cloudflare 為基礎的團隊儀表板、Phase 5 的企業/合規層級。以上所有項目的工程細節都在 [`CLAUDE.md`](CLAUDE.md) 裡，這裡不重複。

## 貢獻

如何貢獻請見 [`CONTRIBUTING.md`](CONTRIBUTING.md)，完整的工程慣例與 repo 地圖見 [`CLAUDE.md`](CLAUDE.md)。最有價值的貢獻，是回報一個誤判(一個正常指令被 Damping 錯誤攔下)，或是找到某條預設規則真的能被繞過的方法。這兩種都會變成永久的迴歸測試情境，而不是修一次就算了。

## 發布新版本

切一個發布版本是刻意、由人手動觸發的動作——推送一個 `v*` tag 是唯一會觸發 `.github/workflows/release.yml` 的方式；一般推送到 `main` 不會觸發任何東西。

```
git tag -a vX.Y.Z -m "..."
git push origin main         # 如果 main 本身還沒推上去的話
git push origin vX.Y.Z
```

這會跑 `goreleaser release --clean`(設定檔 `.goreleaser.yaml`)：跨平台編譯全部 5 種目標、把壓縮檔跟 `checksums.txt` 發布成一個 GitHub Release，並把更新後的 Homebrew cask 推送到 `amplify-lab/homebrew-tap`。

**切 tag 之前**，先在本機做一次不會真的發布任何東西的健檢：

```
goreleaser release --snapshot --clean --skip=publish
```

**切完 tag 之後**，要確認發布真的成功了——不要只看 workflow 的 pass/fail 徽章(下面「已知缺口」有講為什麼這個徽章現在不完全可靠)：

```
gh run list --repo amplify-lab/damping --limit 1                        # Release workflow 有沒有真的跑
gh release view vX.Y.Z --repo amplify-lab/damping --json assets,isDraft # 5 個壓縮檔加 checksums.txt 是不是真的都在，而且不是草稿
curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | DAMPING_VERSION=vX.Y.Z DAMPING_INSTALL_DIR=/tmp/damping-verify sh && /tmp/damping-verify/damping version
```

最後這一行才是真正的證明——它會實際跑一次真實發布出去的壓縮檔，連同 checksum 驗證，不是只看 GitHub API 回傳的中繼資料。

**已知缺口**：`https://damping.dev/install` 目前還是導向網域註冊商的預設停放頁(`/lander`)，不是 `install.sh` 的內容——網域已經註冊了，但這個路徑目前還沒有部署任何東西去回應。需要在這個 repo 之外做 DNS/主機設定(例如 Cloudflare 的轉址規則，或是一個指向 `install.sh` 原始內容的 Pages 部署)。

**已於 `v0.2.1`(2026-07-07)解決**：Homebrew cask 推送以前會失敗，錯誤是 `403 Resource not accessible by personal access token`——`HOMEBREW_TAP_GITHUB_TOKEN` 這個 secret 是存在的，但背後的 token 沒有 `amplify-lab/homebrew-tap` 這個 repo 內容的寫入權限。已經用正確的權限範圍重新產生過(由 Tim 本人直接在 GitHub 上操作——這種事絕對不透過 AI 助理經手)，而且是真的驗證過：`v0.2.1` 那次 Release run 的 Homebrew 步驟成功了，`amplify-lab/homebrew-tap/Casks/damping.rb` 現在有真實、正確的 checksum，對應到真正發布的壓縮檔，`curl .../install.sh | sh` 也對著新版本重新端到端驗證過一次。修好 token 之後重跑同一個 tag 的 Release run，先撞到另一個不相干的問題——對一個已經有這些檔案的 release 重複上傳，會得到 `422 ... already_exists` 錯誤——已透過在 `.goreleaser.yaml` 設定 `release.replace_existing_artifacts: true` 解決，這其實也是不管有沒有這次事件都該有的正確設定。

「Release」這個 GitHub Actions run 的 pass/fail 徽章現在是可靠的訊號了——它過去每次發布都是紅的，純粹是因為上面這個 Homebrew 缺口，不代表其他東西真的壞掉(GitHub Release 本身、install.sh、現在連 Homebrew 都是正常運作的，只是徽章一直說反話)。如果未來哪次發布這個徽章又紅了，那就該當成一次真正的迴歸來查，而不是又碰到這個已經修好的老問題。

**另一個獨立的「CI」workflow(每次推送到 `main` 都會跑，不只是切 tag 才跑)從 `v0.2.0`(2026-07-06)起已經是真正全綠了**——驗證這次發布時，順手發現並修掉了三個跟 `v0.2.0` 這次功能開發完全無關、本來就存在的 bug：`golangci-lint-action` 固定在一個(`v6`)無法執行 golangci-lint v2 的版本，而 `go.mod` 的 `go 1.26` 又需要 v2；`securego/gosec` 的 Docker action 在掃描 `core/policy` 時會無聲地把整個 job step 弄死，沒有留下任何錯誤訊息(很可能是巢狀 Docker 造成的資源壓力，已改成直接安裝原生的 gosec binary 來跑)；還有一個效能測試斷言了一個毫秒級的時間預算，在 `-short` 模式下本來就正確地跳過，但在 `-race` 模式下沒有跳過——`-race` 本身的插樁開銷就會超出那個預算，跟真正的執行效能無關。所以跟上面 `damping.dev` 網域那個缺口不一樣，以後不該預期 CI 徽章會是紅的——如果紅了，那就是真的迴歸。

## 安全性

如何回報安全漏洞(包含政策繞過方式)，見 [`SECURITY.md`](SECURITY.md)。

## 授權條款

Apache License 2.0——詳見 [`LICENSE`](LICENSE)。

---

*Damping 由 Amplify Lab 開發，隸屬於牧本科技股份有限公司(台灣註冊實體)——這點跟 Damping 之後的企業版/主權治理層級有關，跟上面的個人/免費版無關。*
