from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.crud.finding import get_finding, update_finding_llm_summary
from app.db.database import get_db_session
from app.llm.client import OllamaError, generate
from app.llm.prompts import build_finding_analysis_prompt


router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.post("/{finding_id}/analyze")
def analyze_finding_api(
    finding_id: str,
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    finding = get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    prompt = build_finding_analysis_prompt(finding)
    try:
        llm_summary = generate(prompt)
    except OllamaError as exc:
        raise HTTPException(status_code=502, detail="Ollama analysis failed") from exc

    updated = update_finding_llm_summary(
        db,
        finding_id=finding_id,
        llm_summary=llm_summary,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"llm_summary": updated.llm_summary or ""}
