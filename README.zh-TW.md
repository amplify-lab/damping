# Damping

[English](README.md) | **繁體中文**

**一套政策、一份稽核紀錄，終端機跟 MCP 伺服器都算在內。**

你的 AI 編碼 agent（Claude Code、Cursor、Codex，以後還會接更多）跟真實世界之間，Damping 就卡在中間當守門員。agent 想跑一個具破壞性的 shell 指令、或是呼叫一個高風險的 MCP 工具之前，Damping 會先攔下來對照政策，讓你有機會喊停；不管你最後是放行還是擋掉，都會記一筆——而且不分終端機還是 MCP，全部記在同一份紀錄裡。

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete of a path that isn't a known regenerable build/cache directory (node_modules, dist, build, ...) — for your home directory, filesystem root, or a configured protected path, this could destroy irreplaceable data

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

## 「阻尼」是什麼意思

*阻尼*（damping）是物理學的詞，指的是把暴衝、失控振盪的系統拉回穩定範圍的那股力——重點是「拉回穩定」，不是「讓它停下來」。這也是整個產品的核心想法：**治理 AI agent 不是要把它綁死，而是要抑制它可能失控的地方，讓它能穩穩地跑下去。**（Amplify Lab 底下幾個產品都用物理概念命名，這是其中一個。）

## 快速開始

### 1. 裝起來

```
curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | sh
damping init                # 自動偵測 Claude Code / Cursor / Codex，裝上預設政策，把 hook 接好
```

Homebrew 現在也能裝了：`brew install amplify-lab/tap/damping`（注意這是我們自己的 tap，不是官方 homebrew-core，`amplify-lab/tap` 這個前綴不能省，單打 `brew install damping` 是裝不到的）。`curl -sSL https://damping.dev/install | sh` 這個捷徑目前還沒接好，下面「怎麼部署」那段會講清楚差在哪。不管走哪條路，裝到的都是同一份、有做過 checksum 驗證的真正執行檔。

`damping init` 跑完會告訴你每個偵測到的 agent 有沒有成功接上，最後還會建議你玩一次 demo（`rm -rf /tmp/test`）——就是下面第 2 步。

### 2. 看它真的攔一次

叫你的 agent（Claude Code、Cursor、Codex 都行）去跑一個 Damping 預設政策會判定為危險的指令，最安全的示範就是 `rm -rf /tmp/test`，不會動到你真正的東西。要注意畫面會出現在你自己的終端機，不是 agent 的對話視窗裡——Damping 有自己一套獨立的確認提示，走 `/dev/tty`，跟觸發它的是哪個 agent 完全無關：

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete of a path that isn't a known regenerable build/cache directory (node_modules, dist, build, ...) — for your home directory, filesystem root, or a configured protected path, this could destroy irreplaceable data

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

- **`a`** / **`d`**：只管這一次，放行或擋掉。
- **`A`** / **`D`**：把這次的選擇記下來（寫成一條精準比對的規則存進政策檔），下次同一個指令就不會再問了。像是 build script 裡固定會跑的 `rm -rf ./dist/*`，確認過沒問題之後，選這個以後就不用再被問一次。

### 3. 回頭看發生了什麼事

不管是放行、被問、還是被擋，也不管是終端機還是 MCP，Damping 判斷過的每一筆都會進到同一份稽核紀錄：

```
damping log                        # 把攔過的東西全部重播一次，兩種管道都有
damping log --risk critical        # 只看 critical 等級的
damping log --channel mcp --since 24h
damping log --follow               # 像 tail -f 一樣即時盯著看
```

或是直接開一個網頁介面看，完全不用另外設定：

```
damping dashboard                  # 預設綁在 127.0.0.1:4243
```

<img src="docs/assets/dashboard-demo.png" alt="damping dashboard showing a filterable event table with per-session risk sparklines, mixing CLI and MCP channel events across all four risk tiers" width="700">

*（這張是拿灌了測試資料的本機紀錄實際跑出來的畫面，不是示意圖。兩種管道、四種風險等級、allow/deny/prompt 三種結果、兩個不同 agent 全部混在一起——這正是重點：一張表就搞定，不用每個工具各自開一個。）*

### 4. MCP 伺服器也一起罩

把 MCP client 的設定改成指向 Damping，不要直接指向真正的伺服器：

```
damping mcp wrap -- npx @some-org/example-mcp-server
```

Damping 會把真實伺服器的工具原封不動列出來，但每次呼叫都先經過跟終端機一模一樣的政策引擎跟稽核紀錄，過關了才轉送過去。從 client 那邊看，包出來的伺服器行為完全沒變，唯一差別是危險的工具呼叫現在也擋得住了，跟擋一個 shell 指令是同一套邏輯。

### 5. 平常用得到的指令

```
damping status                     # 現在有沒有開、用哪個政策、接了哪些 agent
damping doctor                     # 健檢——hook 有沒有掛好、政策檔正不正常、有沒有降級模式紀錄
damping policy test "rm -rf ~/"     # 拿一個指令乾跑一次看政策怎麼判，不會真的動手
damping off --for 30m               # 暫停執行（唯一官方支援的停用方式，原因寫在 docs/threat-model.md §4）
```

完整指令列表在 [`docs/cli-reference.md`](docs/cli-reference.md)。

## 怎麼部署

**各種安裝方式，目前真正能不能用**——這是實測過的結果，不是憑印象亂寫：

| 方式 | 現況 |
| --- | --- |
| `curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh \| sh` | **能用**——會自動抓對應平台的壓縮檔（從最新的 GitHub Release）、驗 SHA-256 checksum、裝到 `/usr/local/bin`（想改路徑用 `DAMPING_INSTALL_DIR`，想指定版本用 `DAMPING_VERSION=vX.Y.Z`） |
| 去 [GitHub Releases](https://github.com/amplify-lab/damping/releases) 手動下載 | **能用**——每次發版都有 5 種平台的壓縮檔（linux/darwin 各配 amd64/arm64，加上 windows/amd64），還有 `checksums.txt` |
| `brew install amplify-lab/tap/damping` | **能用**（`v0.2.1` 之後）——`amplify-lab/homebrew-tap` 是我們自己的 tap，不是官方那個，`amplify-lab/tap` 這個前綴一定要打，單打 `brew install damping` 裝不到 |
| `curl -sSL https://damping.dev/install \| sh` | **還不能用**——`damping.dev` 這個網域有註冊了，但還沒把這個路徑接到 `install.sh` 的內容上 |

**要怎麼更新**：目前還沒有 `damping update` 這種指令，想更新就把當初裝的方式重跑一次就好（`curl ... | sh` 或 `brew upgrade amplify-lab/tap/damping`），會自動抓到最新版。有一點要注意：升級這件事**不會**動到你的政策檔——`damping init` 本來就設計成不會覆蓋已經存在的 `~/.damping/policy.yaml`，就是為了不要把你自己加的 `always_allow`/`always_deny`/`protected_paths` 蓋掉。所以新版 binary 多出來的規則，不會自動跑進一台已經裝過的機器裡。`damping doctor` 現在會幫你檢查政策檔是不是少了目前版本內建的規則，少了會提醒你；真的想刷新就跑 `damping init --force`（這個指令是整份覆蓋，記得自己客製化的東西要先備份、事後補回去）。

**想整個團隊一起用，不只是自己裝**：V1 目前沒有集中管理或推送式的部署機制，每個人都要自己在自己機器上跑 `damping init`，而且每台機器的政策檔彼此獨立、互不影響。如果現在就想讓全團隊套用同一份政策，比較實際的做法是自己想辦法散布 `policy.yaml`（丟進團隊的 dotfiles repo，或寫個小 script 在 `damping init` 之後自動蓋過去），而不是等 Damping 內建什麼機制——集中式的政策分發跟團隊管理是 Phase 5 才會做的事，現在還沒有。

**怎麼確認真的裝成功了**，不管哪台機器都適用：

```
damping doctor      # hook 有沒有掛好、政策檔正不正常、有沒有降級模式紀錄——有問題會回傳 exit code 4
damping status      # 現在是不是 ON、用哪個政策檔、實際接了哪些 agent
```

這兩個都是唯讀的，重複跑也不會怎樣——`damping doctor` 是這裡面唯一「出包會回傳非 0 exit code」的，很適合寫進 onboarding 檢查清單或健檢腳本。不過光看「有沒有裝上」還不夠，真正能證明它「有在運作」的方式還是上面第 2 步的 demo：實際叫 agent 跑一次 `rm -rf /tmp/test`，親眼看到攔截畫面跳出來，而不是只確認 `$PATH` 找得到這支執行檔而已。

**要暫停或整個移除**：`damping off`（可以加 `--for 30m`）是官方支援的暫停方式——為什麼不建議直接刪掉執行檔了事，`docs/threat-model.md` §4 有講原因。真的要整個移除的話：刪掉裝好的執行檔、刪掉 `~/.damping/`，再把 `damping init` 寫進 `~/.claude/settings.json` / `~/.cursor/hooks.json` / `~/.codex/hooks.json` 裡的那幾行 hook 設定拿掉就好（拿掉之後跑 `damping doctor` 會顯示這個 hook 不見了，可以拿來確認真的清乾淨了）。

## 為什麼不乾脆用 dcg、Aegis 或 Pipelock 就好

講白一點，如果你要的就只是「擋掉 `rm -rf`」，[dcg](https://github.com/Dicklesworthstone/destructive_command_guard) 已經很成熟、很多人在用，做得也不錯，真的可以考慮它。Damping 賭的是另一件事：**同一套政策引擎、同一份稽核紀錄，MCP 工具呼叫也算進去**，不是只顧終端機。你的 agent 不管在哪一邊踩到規則，跑一次 `damping log` 兩邊的紀錄都會在同一份裡，還能照管道篩選：

```
$ damping log --channel cli
$ damping log --channel mcp
```

跟這個領域裡幾個比較接近的工具，老實比一輪——人家贏在哪就直接講，不裝作沒有這回事（`docs/00-統一開發計畫（定案版）.md` §三 有這張表背後完整的研究）：

| | 贏在哪 | 沒做到什麼 |
| --- | --- | --- |
| **[dcg](https://github.com/Dicklesworthstone/destructive_command_guard)** | 1,150+ 星、每天都有人 commit，整合了 10 種以上的 agent（Claude Code、Codex、Gemini CLI、Copilot CLI、Cursor、Grok、Aider），內建的規則也比 Damping 現在多 | 只做 CLI，MCP 工具呼叫完全沒涵蓋，也沒有跨管道的稽核紀錄 |
| **[Aegis](https://github.com/Justin0504/Aegis)** | 這領域裡跟「一套政策 + 稽核 gateway」概念最接近的 OSS 專案，有加密稽核紀錄、人工核可流程，還支援 9 種以上框架的 SDK | 走的是 gateway/SDK、執行期中介這種部署模式，不是輕量的 per-agent CLI+MCP hook——形態完全不一樣，對個人開發者的終端機來說沒辦法直接拿來換 |
| **[Pipelock](https://github.com/luckyPipewrench/pipelock)** | 專門做 MCP/HTTP/A2A 流量的 AI agent 防火牆，抓外洩、SSRF、prompt injection，還會簽章存證 | 它回答的是「資料有沒有流出去」，不是「這個動作到底做了什麼、誰核准的」——沒有細到每個工具呼叫的授權機制，也沒有統一的稽核紀錄 |
| **Damping** | 同一套引擎、同一份紀錄，終端機跟 MCP 伺服器一起顧，鎖定個人開發者的規模，用真正的 AST 解析（`mvdan/sh`）不是正規表達式抓，零遙測，單一靜態 Go 執行檔 | 四個裡面最新出來的——內建規則比 dcg 少；沒有加密稽核紀錄，也沒有 gateway 部署模式，這兩個是 Aegis 的強項 |

這個領域裡目前沒有其他人在個人開發者這個規模上，把 CLI 跟 MCP 統一在同一套引擎、同一份稽核紀錄底下——這才是真正的差異，不只是「擋一次 shell 指令」的 demo 好看而已。

## 這些是它要防的真實事故

下面每一條規則，都是因為真的發生過、有紀錄可查的事故才存在的，不是憑空想像。每一條規則都拿事故當時實際的指令樣態測過，寫進來之前也重新查證過一次。

| 發生了什麼事 | 攔下它的規則 |
| --- | --- |
| 一個 Claude Code session 跑了 `rm -rf`，把使用者整個家目錄清空了。 | `destructive.rm_rf_protected` |
| 一個 Cursor agent 被明確告知「不要執行任何東西」，結果還是刪了 70 個檔案。 | `destructive.rm_rf_protected` |
| 一個 Replit agent 把正式資料庫刪了，某客戶公司 1,200 多位主管都受影響。 | `destructive.sql_drop_truncate`（現在也管沒有 `WHERE` 條件的 `UPDATE`/`DELETE`，還有 `redis-cli FLUSHALL`/`FLUSHDB`） |
| 一個跑在沙箱裡的 agent 靠 `/proc/self/root/usr/bin/npx` 這條路徑繞過黑名單，被抓到之後乾脆把整個沙箱關掉。 | `destructive.proc_sandbox_bypass` |
| 一個 Claude Code session 對 DataTalks.Club 真正在跑的 AWS 帳號下了 `terraform destroy`（換機器之後留了一份過期的 Terraform state 檔），把 VPC/RDS/ECS 整套都刪光——2.5 年的課程資料、大約 194 萬筆資料庫紀錄，是靠 AWS 主控台裡一份本來看不到的快照才救回來的（[Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/claude-code-deletes-developers-production-setup-including-its-database-and-snapshots-2-5-years-of-records-were-nuked-in-an-instant) 有報導，[incidentdatabase.ai](https://incidentdatabase.ai/cite/1424) 收錄為事故 #1424）。 | `destructive.iac_destroy` / `destructive.iac_apply_unreviewed`（同時也管 `pulumi destroy`/`up --yes`、`cdk destroy`，還有跳過工具自己人工審查那關就硬上的 `terraform apply`/`pulumi up`） |
| TrapDoor 這波攻擊（2026 年 5 月，[socket.dev 查過](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)）：在 `CLAUDE.md`/`.cursorrules` 裡藏了指示，誘導 Claude Code 跟 Cursor 跑一個假的「安全掃描」，趁機把 SSH 金鑰、AWS 憑證，還有 Solana/Sui/Aptos 錢包的 keystore 都偷走。 | `destructive.secret_exfiltration`——這是通用的憑證外洩規則，任何受保護路徑被讀走、送到不在白名單裡的地方就會觸發，不是專門抓加密貨幣的；錢包 keystore 只是加進同一份保護清單裡而已 |
| Anthropic 自家 Claude Code 現在會原生擋下 `git reset --hard`/`clean -fd`/`stash drop`/`checkout -- .` 跟 `terraform`/`pulumi`/`cdk destroy`，是最近一則 CHANGELOG 才有的——但只在 Claude Code 自己的「auto」模式下、只管這一家，判斷方式也是靠模型自己拿捏，不是寫死的規則。 | `destructive.git_history_destructive`、`destructive.iac_destroy`——不管你用哪個工具都一樣管，判斷方式也是固定的，所以不管你用哪個 agent、哪個模式，防護都在 |
| CVE-2025-53773（GitHub Copilot）：一個 prompt injection payload 把 `chat.tools.autoApprove: true` 寫進 `.vscode/settings.json`——這只是單純改個檔案，不是下指令，結果之後每個終端機指令都不用確認就直接跑了。CVE-2026-50549（外號「DuneSlide」，Cursor，CVSS 給到 9.8）：一次 prompt injection 引發的 symlink 寫入，逃出了 Cursor 自己的沙箱，還把沙箱的輔助執行檔蓋掉。這兩個都是純粹靠寫檔案下手，只盯 shell 指令的攔截器完全看不到。 | `destructive.agent_permission_escalation`、`destructive.git_hook_write`、`destructive.npm_lifecycle_script_write`——Damping 現在也會攔 Claude Code 的 `Write`/`Edit`/`MultiEdit`，不只是 `Bash`。**目前只有 Claude Code 有**——Cursor 沒有能真正擋下來的 pre-write hook（所以就算做了這個擴充，DuneSlide 那次也擋不住），Codex 的 `PreToolUse` 也完全不會為這幾個工具名稱觸發；細節看 [`docs/cli-reference.md`](docs/cli-reference.md) §11 |
| 一位 DevOps 工程師自己寫的檢討：在正式環境用 K9s 操作，對錯的 namespace 下了 `kubectl delete`，讓正式環境的 ingress/負載平衡斷線大概 40 分鐘——接著 ArgoCD 自動同步又重新部署一次，把 RabbitMQ 的 PersistentVolume 也刪了，資料就這樣沒了（[Gustavo Zanotto，2024 年 1 月](https://medium.com/@gustavo.zanotto/the-day-i-deleted-the-production-ingress-namespace-in-k8s-9ba4f56a7f05)）。 | `destructive.kubectl_bulk_delete` |
| Amazon 自家「Amazon Q Developer」VS Code 擴充套件有一版被動過手腳（v1.84，上線大概 48 小時，2025 年 7 月）：裡面塞了一段 prompt，叫 AI agent（用 `--trust-all-tools --no-interactive` 這種完全不用確認的方式）去找本機的 AWS profile，然後跑 `aws ec2 terminate-instances`、`aws s3 rm`、`aws iam delete-user` 把使用者的雲端資源清光；AWS 後來證實真的被動過手腳，也把那個版本下架了（[The Register](https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/)）。 | `destructive.cloud_cli_mass_delete` |
| WhisperGate（幕後是 DEV-0586，後來改名 Cadet Blizzard），2022 年 1 月 13 日第一次針對烏克蘭政府/組織下手：偽裝成勒索軟體的兩段式抹除工具，先把 Master Boot Record 蓋掉，再把檔案內容整個覆寫，裝置直接報銷，沒有真正的復原辦法（[Microsoft MSTIC](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)）——這正是對整顆裝置下 `dd`/`shred`/`blkdiscard` 會造成的效果。 | `destructive.raw_device_write` |
| 2025 年 12 月 5 日，有人把冒充正牌 `finch` 的惡意套件 `finch-rust`，還有偷憑證用的 `sha-rust`，直接發布到 crates.io 上——crates.io 團隊當天就把帳號停權、兩個套件都刪了（[Rust Blog](https://blog.rust-lang.org/2025/12/05/crates.io-malicious-crates-finch-rust-and-sha-rust/)）。 | `destructive.cargo_publish_unreviewed` |
| 2019 年 8 月，有人入侵了某個維護者的 RubyGems.org 帳號，拿去發布了四個惡意版本（1.6.10–1.6.13）的熱門套件 `rest-client`，其中 1.6.13 版藏了偷憑證兼挖礦的後門——CVE-2019-15224（[GitHub issue](https://github.com/rest-client/rest-client/issues/713)）。 | `destructive.gem_push_unreviewed` |
| Socket 的威脅研究團隊抓到 npm 套件 `mysql-dumpdiscord`（還有配套的 PyPI/RubyGems 套件）會偷讀 `.env`/`config.json`/`ayarlar.json`，再包成 JSON 送到寫死的 Discord webhook 網址——這是一整波把 Discord webhook 當成免費、不用驗證的 C2/外洩管道的攻擊行動，橫跨 npm、PyPI、RubyGems 三個生態系（[Socket](https://socket.dev/blog/weaponizing-discord-for-command-and-control)）。 | `destructive.webhook_exfiltration` |

特別提一下加密貨幣/錢包這塊：上面講的憑證外洩路徑是真的存在，而且現在就直接衝著 Claude Code/Cursor 來（TrapDoor 那個）。至於直接攔截轉帳指令本身（`cast send`、`solana transfer` 這類）則是更窄、更 Web3 專屬的情境，證據沒那麼多——列為以後可能會做的項目，現在還沒做，這裡也不誇大講。

**老實講，現在還做不到的，不會裝作已經解決了：** 有兩起真實的供應鏈攻擊（2025-2026）值得特別點出來講，而不是硬塞進上面那張表，因為 Damping **現在真的攔不住這兩個**——Nx/s1ngularity 那次攻擊（靠一個被動過手腳的 AI 編碼 agent，外洩了 2,349 組憑證，把偷來的東西推到一個新開的公開 `gh repo create` repo 裡），還有 2026 年 5 月的 node-ipc 後門（靠 DNS TXT 查詢當通道偷憑證）。不管是 `gh repo create` 這招還是靠 DNS 外洩，現在都不在 `destructive.secret_exfiltration` 能抓到的範圍內——這兩個都是真實、範圍很明確的未來候選規則，不是現在就已經涵蓋的東西。

## 現在真的做到了什麼（V1 / Phase 1）

以下這些都已經做完、有測試在把關——不是畫大餅，是現在的實際狀況：

- CLI shell 指令攔截，用的是真正的 AST 解析，不是正規表達式硬湊，涵蓋 24 條預設規則（破壞性刪除、強制推送、破壞性 SQL/Mongo/Redis 操作、遞迴權限變更、沒查核的安裝 pipeline、編碼過的 payload、沙箱繞過路徑、infra-as-code 的 destroy/沒審查就 apply、破壞性的 git 歷史操作、憑證外洩、kubectl/雲端 CLI 大量刪除、對整顆裝置的原始寫入、沒審查的 crates.io/RubyGems 發布、聊天軟體 webhook 外洩，還有更多）——完整清單跟每一條背後的真實事故，見 [`docs/threat-model.md`](docs/threat-model.md) 跟上面「這些是它要防的真實事故」那節。
- Claude Code 的 `Write`/`Edit`/`MultiEdit` 工具呼叫，現在跟 `Bash` 一樣會被顧到——上面 24 條規則裡有 3 條專門抓危險的*檔案寫入*（agent 權限升級、git-hook 埋後門、npm 生命週期腳本注入），不只是抓危險指令而已。目前只支援 Claude Code；Cursor 跟 Codex 為什麼還沒做，原因寫在 [`docs/cli-reference.md`](docs/cli-reference.md) §11。
- `damping mcp wrap`——同一套政策引擎、同一份稽核紀錄，MCP 工具呼叫也一樣管，不只是終端機。
- 本機的 `damping dashboard`（畫面如上）跟 `damping log`，可以把兩種管道的完整稽核紀錄重播出來——還有風險趨勢圖、觸發最多次的規則排行，以及時間區間/規則 ID 篩選，這兩個圖表都是算在完整歷史紀錄上，不是只看畫面上那幾筆而已。
- 內建 OPA/Rego 政策引擎，可以當作預設 Go 引擎之外的另一個選擇。
- `damping compliance-report demo` / `export`——對日後企業版合規報表的一個早期預覽，而且老實講清楚範圍：`demo` 不用真的部署什麼（用真實、已經在跑的規則湊出一份合成的 30 天資料），`export` 則是拿你自己本機真正的稽核紀錄跑出同一份報表，支援 markdown/text/JSON，還有自帶圖表的 HTML 格式。講清楚這不是完整的 Phase 5 企業版功能（沒有地端部署、沒有 AD/LDAP 身分綁定、沒有 PostgreSQL）——細節在 [`docs/cli-reference.md`](docs/cli-reference.md) §7.1。
- `noninteractive_prompt_fallback`——一個要自己開才會生效的設定，讓一條該問人的規則，在旁邊沒有終端機可以問的時候（像是背景跑、沒人盯著的 agent），改成照風險等級決定放行還是擋下，不會再像以前那樣不管三七二十一直接擋掉。
- 170 個 BDD 情境，全部接到真實程式碼跑得過，不是寫好看的。
- 跨平台的發布流程（Homebrew、一行安裝指令、linux/darwin 的 amd64/arm64 都有 GitHub Release）。

還沒做的：Phase 3 完整的企業版 Gateway（OAuth 2.1、防止 confused-deputy）、Phase 4 用 Cloudflare 做的團隊儀表板、Phase 5 的企業/合規層級。上面每一項的工程細節都寫在 [`CLAUDE.md`](CLAUDE.md) 裡，這裡不重複講。

## 想貢獻

怎麼貢獻看 [`CONTRIBUTING.md`](CONTRIBUTING.md)，完整的工程慣例跟 repo 架構在 [`CLAUDE.md`](CLAUDE.md)。最有價值的貢獻，是回報一個誤判（某個正常指令被 Damping 錯攔下來了），或是找到某條預設規則真的能被繞過的方法。這兩種都會變成永久留下來的迴歸測試，不是修一次就丟掉。

## 怎麼發新版本

切一個發布版本是刻意、要人手動觸發的動作——推一個 `v*` tag 才是唯一會觸發 `.github/workflows/release.yml` 的方式，平常推 `main` 什麼都不會發生。

```
git tag -a vX.Y.Z -m "..."
git push origin main         # 如果 main 本身還沒推上去的話
git push origin vX.Y.Z
```

這會跑 `goreleaser release --clean`（設定寫在 `.goreleaser.yaml`）：跨平台編出全部 5 種目標、把壓縮檔跟 `checksums.txt` 發成一個 GitHub Release，還會把更新後的 Homebrew cask 推到 `amplify-lab/homebrew-tap`。

**切 tag 之前**，先在本機做一次不會真的發布出去的健檢：

```
goreleaser release --snapshot --clean --skip=publish
```

**切完 tag 之後**，要確認真的發成功了——不要只看 workflow 那個 pass/fail 的徽章（下面「已知還沒解決的問題」有講為什麼這個徽章現在不完全可信）：

```
gh run list --repo amplify-lab/damping --limit 1                        # Release 這個 workflow 到底有沒有真的跑
gh release view vX.Y.Z --repo amplify-lab/damping --json assets,isDraft # 5 個壓縮檔加 checksums.txt 是不是真的都在，而且不是草稿
curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | DAMPING_VERSION=vX.Y.Z DAMPING_INSTALL_DIR=/tmp/damping-verify sh && /tmp/damping-verify/damping version
```

最後這一行才是真正的鐵證——它會真的去抓發布出去的壓縮檔、驗過 checksum，不是只看 GitHub API 回傳的資訊而已。

**已知還沒解決的問題**：`https://damping.dev/install` 現在還是導去網域註冊商的預設停放頁（`/lander`），不是 `install.sh` 的內容——網域是註冊了沒錯，但這個路徑還沒接上任何東西。需要在這個 repo 之外另外搞 DNS/主機設定（比如 Cloudflare 的轉址規則，或是弄一個 Pages 部署把這個路徑指到 `install.sh` 的原始內容）。

**`v0.2.1`（2026-07-07）已經解決**：Homebrew cask 推送以前一直失敗，錯誤是 `403 Resource not accessible by personal access token`——`HOMEBREW_TAP_GITHUB_TOKEN` 這個 secret 是有設，但背後那個 token 沒有 `amplify-lab/homebrew-tap` 的寫入權限。已經重新產生一個權限對的 token 換上去了（Tim 本人直接在 GitHub 上操作，這種事絕對不會透過 AI 助理經手），而且是真的驗證過：`v0.2.1` 那次 Release 的 Homebrew 那一步真的成功了，`amplify-lab/homebrew-tap/Casks/damping.rb` 現在有正確的 checksum，對得上真正發布的壓縮檔，`curl .../install.sh | sh` 也對著新版本重新跑過一次確認沒問題。token 修好之後重跑同一個 tag 的 Release，先撞到另一個不相干的問題——對一個已經有這些檔案的 release 重複上傳會被 GitHub 擋下來（`422 ... already_exists`）——後來在 `.goreleaser.yaml` 加了 `release.replace_existing_artifacts: true` 解決，這其實不管有沒有這次事件，本來就該這樣設定才對。

「Release」這個 workflow 的 pass/fail 徽章現在總算是能信的訊號了——它以前每次發布都是紅的，純粹是因為上面那個 Homebrew 的問題，不代表其他東西真的壞掉（GitHub Release 本身、install.sh、現在連 Homebrew 都是正常的，只是徽章一直講反話）。以後哪次發布這個徽章又紅了，那就真的是出問題了，不會又是這個已經修好的老問題。

**另外一個獨立的「CI」workflow（每次推 `main` 都會跑，不是只有切 tag 才跑）從 `v0.2.0`（2026-07-06）開始已經是真的全綠了**——驗證這次發布的時候，順手抓到並修掉了三個跟這次功能開發完全無關、本來就存在的 bug：`golangci-lint-action` 被鎖在一個（`v6`）沒辦法跑 golangci-lint v2 的版本上，但 `go.mod` 的 `go 1.26` 又非得要 v2 不可；`securego/gosec` 的 Docker action 在掃 `core/policy` 的時候會無聲無息把整個 job 搞死，連錯誤訊息都沒留（八成是巢狀 Docker 造成的資源吃緊，已經改成直接裝原生的 gosec 來跑）；還有一個效能測試設了毫秒級的時間上限，在 `-short` 模式下本來就會正確跳過，但 `-race` 模式下沒跳過——`-race` 本身插樁造成的開銷就會爆掉那個上限，跟程式真正跑得快不快沒關係。所以跟上面 `damping.dev` 那個網域問題不一樣，以後 CI 徽章應該不會再是紅的——如果紅了，那就是真的出包了。

## 安全性

怎麼回報安全漏洞（包括政策被繞過的方法），看 [`SECURITY.md`](SECURITY.md)。

## 授權

Apache License 2.0——詳見 [`LICENSE`](LICENSE)。

---

*Damping 是 Amplify Lab 開發的，隸屬於牧本科技股份有限公司（台灣註冊的實體）——這點跟 Damping 以後的企業版/主權治理層級有關，跟上面講的個人版/免費版沒關係。*
