# Skill 包审查算子

## 1. 算子简介

`Skill 包审查` 用于在 DataMate 清洗流程中对 Skill 压缩包进行自动审查，输出结构化 JSON 结果。

支持格式：

- `.zip`
- `.tar.gz`

审查维度（固定 4 项）：

1. 代码静态检查
2. Skill 规范检查
3. 敏感信息检查
4. Prompt 注入检查

## 2. 输入与输出

- 输入模态：`text`
- 输出模态：`text`
- 输出文件：`*.txt`
- 输出内容：审查结果 JSON（总分、结论、分项详情、模型使用状态）

## 3. 高级配置说明

### 模型参数配置（独立于设置页面）

- `模型 Base URL（必填）`：OpenAI 兼容地址（如 `https://api.siliconflow.cn/v1`）
- `模型名称（必填）`：调用的模型 ID（如 `Pro/zai-org/GLM-5`）
- `模型 API Key（必填）`：模型密钥（当前参数面板仅支持普通输入框）
- `模型提供商（可选）`：仅用于结果展示
- `采样温度`、`模型超时（秒）`：控制语义层调用行为

语义层固定开启。若必填模型参数缺失，算子会直接报错并提示缺失项。

## 4. 在 DataMate 中使用

1. 创建数据清洗任务并选择源/目标数据集。
2. 在算子编排中添加 `Skill 包审查`。
3. 按需设置高级配置，建议语义层场景保持：
   - 填写必填的模型参数（`Base URL`、`模型名称`、`API Key`）
4. 执行任务，在任务文件中查看或下载输出结果。

## 5. 结果字段说明

核心字段：

- `score`：综合分（0-100）
- `overall`：`approved` / `rejected`
- `risk`：`low` / `medium` / `high`
- `sections`：4 个审查维度的评分与问题明细

模型相关字段：

- `review_engine`：`rules-only` / `operator-llm` / `rules-fallback`
- `semantic_review.configured_in_operator`：模型是否来自算子参数配置
- `semantic_review.model_name`：实际使用的模型名称
- `semantic_review.model_url`：实际调用的模型 Base URL
- `semantic_review.error`：语义层失败原因（成功时为 `null`）

## 6. 注意事项

- 当前参数面板不支持密码类型输入框，`模型 API Key` 会以普通文本输入方式保存与展示。
- 规则层始终生效；语义层用于补充解释与风险收敛，不会替代基础规则扫描。
