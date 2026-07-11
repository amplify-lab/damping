package i18n

// ruleReasonsZhTW is a curated Traditional Chinese translation of every
// rule description shipped in cli/policies/default.yaml, keyed by rule id.
// Deliberately NOT stored in policy.yaml itself or in core/policy — see
// this file's own package doc comment for why. Command names, flags
// (--all, --prune, -auto-approve), paths (/etc, /usr), and rule-id
// cross-references are kept in their original form, matching this
// project's own README.zh-TW.md convention: a technical audience reads
// those as-is regardless of surrounding language, and mistranslating a
// flag name would make the description actively wrong, not just informal.
//
// Precision matters here more than for ordinary prose: this text is shown
// to a human at the exact moment they're deciding whether to let a
// destructive command through. Every entry below was translated against
// the real matcher's behavior (core/policy/rules*.go), not just the
// English sentence — see i18n_test.go's completeness check, which fails
// the build the day a new rule ships in default.yaml without a matching
// entry here (a translation being *behind* is fine and falls back to
// English per Reason's own doc comment; this test exists to make the gap
// visible, not to force same-day translation).
var ruleReasonsZhTW = map[string]string{ // #nosec G101 -- gosec's hardcoded-credential heuristic false-positives on this large map[string]string literal; every value here is translated rule-description prose, not a secret
	"destructive.rm_rf_protected": "遞迴＋強制刪除你的家目錄、檔案系統根目錄、政策設定的受保護路徑，或系統關鍵目錄（/etc、/usr、/var 等）——可能摧毀無法復原的資料，甚至讓整台機器故障",

	"destructive.rm_rf_unrecognized_path": "遞迴＋強制刪除一個路徑，這個路徑不是已知可重新產生的建置／快取目錄（node_modules、dist、build 等），也不是作業系統的暫存空間（/tmp、/var/tmp），但同時也不屬於 destructive.rm_rf_protected 涵蓋的那種真正災難性目標——值得跳出來確認一下，但嚴重程度比刪掉家目錄低了整整一個數量級，是真的差很多",

	"destructive.git_push_force": "強制推送（force-push）可能覆蓋遠端的歷史紀錄",

	"destructive.sql_drop_truncate": "透過 shell 呼叫的資料庫客戶端執行的 DROP TABLE／TRUNCATE、沒有 WHERE 條件的 UPDATE 或 DELETE（SQL 客戶端）、dropDatabase()／collection.drop()／沒有篩選條件的 deleteMany()／remove()（mongosh），或 FLUSHALL／FLUSHDB（redis-cli）",

	"destructive.chmod_777_recursive": "以遞迴（-R）方式把權限改成全域可寫（777）",

	"destructive.curl_pipe_sh_unallowlisted": "從不在 allowlisted_install_domains 白名單裡的網域執行 curl|sh、curl|bash、curl|zsh、wget|sh、wget|bash 或 wget|zsh",

	"destructive.encoded_payload_pipe": "把 base64 解碼（或類似手法）的內容直接接進 shell／eval 執行",

	"destructive.proc_sandbox_bypass": "已知透過 /proc 路徑繞過沙箱限制的寫法",

	"destructive.dynamic_command_construction": "指令名稱是動態組合出來的（例如指令替換），沒辦法用靜態方式解析出實際內容",

	"destructive.write_protected_path": "把輸出重導向（>、>> 等）寫進受保護路徑",

	"mcp.destructive_tool_call": "MCP 伺服器自己宣告為破壞性的工具（ToolAnnotations.DestructiveHint）",

	"self_protection.damping_off_attempt": "Agent 透過自己的 Bash 工具呼叫試圖執行「damping off」（Ona 事故的那種失效模式）——如果是人類自己在終端機直接下這個指令，永遠不會碰到這條規則",

	"destructive.iac_destroy": "terraform／pulumi／cdk destroy——就是在一起真實、有紀錄的事故中把正式環境帳號整個刪掉的那種指令（agent 當時判斷「清乾淨重來」）",

	"destructive.iac_apply_unreviewed": "terraform apply／pulumi up 加上自動核准／跳過預覽的旗標——跳過了工具自己內建的人工審查步驟，這正是真實事故裡的根本原因",

	"destructive.git_history_destructive": "git reset --hard、clean -f*、stash clear／drop、checkout -- .（捨棄所有本機變更），或 filter-branch／filter-repo（改寫歷史紀錄）——強制推送之外的破壞性 git 操作",

	"destructive.secret_exfiltration": "讀取已知的敏感路徑（protected_paths 裡的 SSH／AWS／加密貨幣錢包／其他憑證檔案），並送到不在 allowlisted_egress_domains 白名單裡的網路目的地",

	"destructive.agent_permission_escalation": "寫入 agent／IDE 的設定檔（.vscode/settings.json、.claude/settings.json），開啟了自動核准／跳過確認的設定鍵，讓之後的工具呼叫完全繞過人工確認",

	"destructive.git_hook_write": "寫入的目標是 .git/hooks/ 底下的檔案——這是一種會在未來 git 操作時自動執行程式碼的持久化機制",

	"destructive.npm_lifecycle_script_write": "寫入 package.json 新增或修改了 postinstall／preinstall／prepare 腳本，npm／pnpm／yarn 會在安裝時自動執行這些腳本",

	"destructive.kubectl_bulk_delete": "kubectl delete namespace，或是對 deployments／pods／pvc／pv／all 下 --all 或 --all-namespaces 的 kubectl delete——一個指令就把整個 namespace 或某一整類工作負載全部刪掉",

	"destructive.cloud_cli_mass_delete": "aws ec2 terminate-instances、aws s3 rm --recursive、aws s3 rb --force、aws rds delete-db-instance、gcloud compute instances delete，或 az vm delete——繞過任何 IaC 管理流程、直接用雲端 CLI 大量刪除／終止正在運作的雲端資源",

	"destructive.raw_device_write": "用 dd、shred 或 blkdiscard 直接對整顆區塊裝置路徑下手（例如 /dev/sda、/dev/nvme0n1），而不是對一般檔案或 loop device——對整顆硬碟做不可逆的原始覆寫",

	"destructive.cargo_publish_unreviewed": "cargo publish（沒加 --dry-run），或 cargo release ... --execute——沒有經過本機審查步驟，直接把 crate 發布到 crates.io",

	"destructive.gem_push_unreviewed": "gem push、gem bump --push、rake release，或 bundle exec rake release——沒有經過本機審查步驟，直接把 gem 發布到 RubyGems.org",

	"destructive.webhook_exfiltration": "用 curl 或 wget 把 POST 資料（或上傳的檔案）送到 Discord／Slack／Microsoft Teams 的 incoming-webhook 網址——一個成本低、不用驗證身分的外洩／C2 通道",

	"destructive.agent_asset_mass_removal": "一次性把 agent 自己安裝的資產全部清光——不管是 `skills remove --all` 或用萬用字元 `'*'`（官方文件寫明是「每個 skill、每個 agent、完全不用確認」的縮寫，不管是用 skills、npx/bunx skills，還是 pnpm/yarn dlx skills 跑的都算）、`claude plugin marketplace remove`（會連鎖移除該 marketplace 底下的所有 plugin）、`claude plugin uninstall --prune`，還是 `claude project purge --all`（會刪掉所有專案的對話紀錄／任務／檔案異動歷史）——這些指令通通沒有「復原」這個選項",

	"destructive.find_delete_protected": "find <path> -delete 的目標是你的家目錄、檔案系統根目錄、政策設定的受保護路徑，或系統關鍵目錄——跟 destructive.rm_rf_protected 涵蓋的是同一組真正災難性的目標，只是這次是透過 find 而不是 rm",

	"destructive.cloud_api_raw_delete": "curl 或 wget 直接呼叫雲端／PaaS 供應商的原始 HTTP API，刪掉整個已部署的資源——Railway 的 GraphQL API（volumeDelete、serviceDelete 之類的 mutation），或是對 Vercel／Netlify／Render／Heroku／DigitalOcean 的 project／site／service／app／droplet 端點下 REST DELETE——完全繞過供應商自己的 CLI，以及 CLI 可能有的任何確認步驟",
}
