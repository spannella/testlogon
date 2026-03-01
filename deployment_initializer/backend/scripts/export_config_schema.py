from __future__ import annotations

import json
from pathlib import Path

from app.config_schema import export_machine_schema


def main() -> None:
    envelope = export_machine_schema().model_dump(mode='json')
    output_path = Path(__file__).resolve().parents[2] / 'frontend' / 'schemas' / 'deployment-config.schema.v1.json'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(envelope, indent=2) + '\n')
    print(f'Wrote schema to {output_path}')


if __name__ == '__main__':
    main()
