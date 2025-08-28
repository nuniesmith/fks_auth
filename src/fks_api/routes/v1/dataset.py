from core.services.dataset import DatasetService
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/dataset", tags=["Dataset Service"])


@router.post("/update")
def update_dataset(dataset_slug: str, currency_pair: str):
    try:
        service = DatasetService(dataset_slug=dataset_slug, currency_pair=currency_pair)
        service.update_main()
        return {"message": "Dataset update completed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
