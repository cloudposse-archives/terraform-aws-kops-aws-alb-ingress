module "label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.3.3"
  namespace  = "${var.namespace}"
  stage      = "${var.stage}"
  name       = "${var.name}"
  delimiter  = "${var.delimiter}"
  attributes = "${var.attributes}"
  tags       = "${var.tags}"
}

module "kops_metadata" {
  source       = "git::https://github.com/cloudposse/terraform-aws-kops-metadata.git?ref=tags/0.1.1"
  dns_zone     = "${var.cluster_name}"
  masters_name = "${var.masters_name}"
  nodes_name   = "${var.nodes_name}"
}

resource "aws_iam_role" "default" {
  name        = "${module.label.id}"
  description = "Role that can be assumed by AWS ALB ingress controller"

  lifecycle {
    create_before_destroy = true
  }

  assume_role_policy = "${data.aws_iam_policy_document.assume_role.json}"
}

locals {
  arns = {
    masters = ["${module.kops_metadata.masters_role_arn}"]
    nodes   = ["${module.kops_metadata.nodes_role_arn}"]
    both    = ["${module.kops_metadata.masters_role_arn}", "${module.kops_metadata.nodes_role_arn}"]
    any     = ["*"]
  }
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    principals {
      type = "AWS"

      identifiers = ["${local.arns[var.permitted_nodes]}"]
    }

    effect = "Allow"
  }
}

resource "aws_iam_role_policy_attachment" "default" {
  role       = "${aws_iam_role.default.name}"
  policy_arn = "${aws_iam_policy.default.arn}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_policy" "default" {
  name        = "${module.label.id}"
  description = "Grant permissions for AWS ALB ingress controller"
  policy      = "${data.aws_iam_policy_document.default.json}"
}

data "aws_iam_policy_document" "default" {

  statement {
    sid = "GrantReadAWSCertificates"

    actions = [
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "acm:GetCertificate"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "OperateEC2"

    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:DeleteSecurityGroup",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVpcs",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:RevokeSecurityGroupIngress"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "OperateELB"

    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteRule",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyRule",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:RemoveTags",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:SetWebACL"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "OperateIAM"

    actions = [
      "iam:CreateServiceLinkedRole",
      "iam:GetServerCertificate",
      "iam:ListServerCertificates"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "OperateWAFRegional"

    actions = [
      "waf-regional:GetWebACLForResource",
      "waf-regional:GetWebACL",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "OperateWAF"

    actions = [
      "waf:GetWebACL"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "OperateTags"

    actions = [
      "tag:GetResources",
      "tag:TagResources"
    ]

    effect = "Allow"

    resources = ["*"]
  },

  statement {
    sid = "Operates"

    actions = [
      "tag:GetResources",
      "tag:TagResources"
    ]

    effect = "Allow"

    resources = ["*"]
  }
}
