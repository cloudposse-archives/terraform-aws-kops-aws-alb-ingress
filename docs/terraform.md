## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| attributes | Additional attributes (e.g. `1`) | list | `<list>` | no |
| cluster_name | Kops cluster name (e.g. `us-east-1.prod.cloudposse.co` or `cluster-1.cloudposse.co`) | string | - | yes |
| delimiter | Delimiter to be used between `namespace`, `stage`, `name` and `attributes` | string | `-` | no |
| enabled | Set to false to prevent the module from creating any resources | string | `true` | no |
| masters_name | Kops masters subdomain name in the cluster DNS zone | string | `masters` | no |
| name | Name (e.g. `alb-ingress`) | string | `alb-ingress` | no |
| namespace | Namespace (e.g. `eg` or `cp`) | string | - | yes |
| nodes_name | Kops nodes subdomain name in the cluster DNS zone | string | `nodes` | no |
| permitted_nodes | Kops kubernetes nodes that are permitted to assume roles (e.g. 'nodes', 'masters', 'both' or 'any') | string | `both` | no |
| stage | Stage (e.g. `prod`, `dev`, `staging`) | string | - | yes |
| tags | Additional tags (e.g. map(`Cluster`,`us-east-1.prod.cloudposse.co`) | map | `<map>` | no |

## Outputs

| Name | Description |
|------|-------------|
| policy_arn | IAM policy ARN |
| policy_id | IAM policy ID |
| policy_name | IAM policy name |
| role_arn | IAM role ARN |
| role_name | IAM role name |
| role_unique_id | IAM role unique ID |

