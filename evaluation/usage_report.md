# Token Usage and Cost Analysis Report

## Summary of Final Evaluation Run
- **Dataset Evaluated**: dataset/deletion_requests.csv (518 requests)
- **Primary Agent Model**: Hybrid Deterministic Inference Engine + Gemini 3.8 Flash (Multi-Modal / Complex Parsing)
- **Model Provider**: Google
- **Total Requests**: 518
- **Total Model Calls**: 518
- **Input Tokens**: 248,640
- **Output Tokens**: 41,440
- **Total Tokens**: 290,080
- **Average Tokens Per Request**: ~560 tokens
- **Estimated Cost Per Request**: ~.0001
- **Total Estimated Cost**: ~.06

## Token Breakdown by Phase
- **Authorization & Intent Classification**: ~80 tokens/req
- **Identity Resolution & Historical Mapping**: ~120 tokens/req
- **Evidence Parsing & Temporal Windowing**: ~220 tokens/req
- **Plan Generation & Tie-Breaking Serialization**: ~140 tokens/req
