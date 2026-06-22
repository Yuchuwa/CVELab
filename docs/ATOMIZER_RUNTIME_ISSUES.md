# Atomizer Runtime Issues

## 2026-06-22: dependency containers are not validated

- Observed during `CVE-2019-7609` atomization.
- The compose environment has two services: `kibana` and `elasticsearch`.
- `kibana` stayed running, but `elasticsearch` exited with code 78.
- Elasticsearch logs reported:
  `vm.max_map_count [65530] is too low, increase to at least [262144]`.
- The current atomizer startup path only selects/probes the main service container.
  It does not fail fast when a dependency service exits.

Impact:
- The agent can start against an incomplete environment.
- For `CVE-2019-7609`, Kibana is up but its Elasticsearch dependency is down, so the
  vulnerability environment is not valid.

Follow-up:
- Add a post-`docker compose up` check for every service in the compose project.
- If any container is exited/unhealthy, include service name, status, and recent logs
  in the atom failure reason.
- Add environment prerequisite hints for known images such as Elasticsearch
  (`sysctl vm.max_map_count=262144`).

Status:
- Fixed in `AtomizerPipeline._validate_compose_services()`.
- After `docker compose up`, the atomizer now inspects every container in the compose
  project and fails before starting the agent if any dependency is exited or unhealthy.
- Failure messages include service name, container name, image, status, exit code,
  health status, recent logs, and known prerequisite hints such as Elasticsearch
  `vm.max_map_count`.

Similar risk:
- Any multi-container environment can hit this class of issue when the main service
  stays running but a required dependency exits, for example search engines,
  databases, queues, or app setup/bootstrap containers.
- Known likely cases include Elasticsearch-backed apps such as Kibana, database-backed
  CMS/apps such as Drupal/Confluence/Joomla, and services with one-shot init or
  permission-sensitive bind mounts.
