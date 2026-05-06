from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.crud.finding import get_finding, update_finding_llm_summary
from app.db.database import get_db_session
from app.llm.client import OllamaError, generate
from app.llm.prompts import build_finding_analysis_prompt
from app.rag.retrieval import retrieve_context_for_finding
from evals.evaluator import evaluate_llm_response
from evals.loader import EvalCase


router = APIRouter(prefix="/api/findings", tags=["findings"])


def _safe_reference_context_for_finding(finding, db: Session) -> list[str]:
    try:
        contexts = retrieve_context_for_finding(finding, db=db)
    except Exception:
        return []

    formatted_contexts: list[str] = []
    for context in contexts:
        title = context.metadata.get("title")
        source_path = context.metadata.get("source_path")
        chunk_index = context.metadata.get("chunk_index")
        summary = context.metadata.get("summary")
        formatted_contexts.append(
            "\n".join(
                [
                    f"source: {title or source_path or context.id}",
                    f"path: {source_path or 'N/A'}",
                    f"chunk: {chunk_index if chunk_index is not None else 'N/A'}",
                    f"summary: {summary or 'N/A'}",
                    f"text: {context.content}",
                ]
            )
        )
    return formatted_contexts


def _eval_case_for_finding(finding) -> EvalCase:
    return EvalCase(
        id=f"finding-analysis-{finding.id}",
        category=finding.category,
        input_finding={
            "id": finding.id,
            "scan_id": finding.scan_id,
            "category": finding.category,
            "scanner": finding.scanner,
            "severity": finding.severity,
            "title": finding.title,
            "rule_id": finding.rule_id,
            "file_path": finding.file_path,
            "line": finding.line,
            "component": finding.component,
            "cve": finding.cve,
            "cwe": finding.cwe,
            "cce_id": finding.cce_id,
            "current_value": finding.current_value,
            "expected_value": finding.expected_value,
            "raw_json_path": finding.raw_json_path,
        },
        expected_constraints=["LLM response must stay grounded in scanner finding metadata."],
        forbidden_outputs=[
            "exploit payload",
            "confirmed false positive",
        ],
    )


@router.post("/{finding_id}/analyze")
def analyze_finding_api(
    finding_id: str,
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    finding = get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    reference_context = _safe_reference_context_for_finding(finding, db)
    prompt = build_finding_analysis_prompt(
        finding,
        reference_context=reference_context or None,
    )
    try:
        llm_summary = generate(prompt)
    except OllamaError as exc:
        raise HTTPException(status_code=502, detail="Ollama analysis failed") from exc

    evaluation = evaluate_llm_response(_eval_case_for_finding(finding), llm_summary)
    if not evaluation.passed:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "LLM analysis failed safety evaluation",
                "failures": evaluation.failures,
            },
        )

    updated = update_finding_llm_summary(
        db,
        finding_id=finding_id,
        llm_summary=llm_summary,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"llm_summary": updated.llm_summary or ""}
