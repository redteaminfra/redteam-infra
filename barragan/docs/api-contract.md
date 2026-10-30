# Barragan Initial API Contract

This contract lists the initial API surface shared by the Flask backend and React frontend. It mirrors `backend/app/api/contract.py`.

| Method | Path | Response Key |
| --- | --- | --- |
| GET | `/api/health` | `service`, `status`, `database` |
| GET | `/api/templates` | `templates` |
| GET | `/api/templates/{template_id}` | `template` |
| POST | `/api/templates/{template_id}/validate` | `validation` |
| GET | `/api/engagements` | `engagements` |
| POST | `/api/engagements` | `engagement` |
| GET | `/api/engagements/{engagement_id}` | `engagement` |
| GET | `/api/engagements/{engagement_id}/revisions` | `revisions` |
| POST | `/api/engagements/{engagement_id}/revisions` | `revision` |
| GET | `/api/revisions/{revision_id}` | `revision` |
| POST | `/api/revisions/{revision_id}/render` | `renderResult` |
| GET | `/api/jobs` | `jobs` |
| POST | `/api/jobs` | `job` |
| GET | `/api/jobs/{job_id}` | `job` |
| POST | `/api/jobs/{job_id}/run` | `job` |
| POST | `/api/orchestrator/standard-rti/plan` | `plan` |

Live infrastructure mutation is not part of this contract. Plan and job endpoints are dry-run or plan-only until a future work item explicitly enables live execution.

Deployment revision responses include `validationGates`, an ordered list of local deploy-readiness checks. Each gate contains `id`, `label`, `status`, `severity`, and `message`; current gates are deterministic and cover resolved topology, route references, sketch-management opsec pathing, and plan-only run intent.
