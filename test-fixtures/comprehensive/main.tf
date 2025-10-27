# EKS Cluster
resource "aws_eks_cluster" "main" {
  name     = "example-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = [aws_subnet.public.id]
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "example-ecs-cluster"
}

resource "aws_ecs_task_definition" "app" {
  family                   = "app"
  container_definitions    = jsonencode([])
}

# ECR Repository
resource "aws_ecr_repository" "app" {
  name = "example-app"
}

# Redshift Cluster
resource "aws_redshift_cluster" "data_warehouse" {
  cluster_identifier = "data-warehouse"
  node_type         = "dc2.large"
  master_username   = "admin"
  master_password   = "Temp12345"
}

# ElastiCache
resource "aws_elasticache_cluster" "cache" {
  cluster_id = "cache-cluster"
  engine     = "redis"
  node_type  = "cache.t3.micro"
}

# OpenSearch Domain
resource "aws_opensearch_domain" "search" {
  domain_name = "example-search"

  cluster_config {
    instance_type = "t3.small.search"
  }
}

# Kinesis Stream
resource "aws_kinesis_stream" "data_stream" {
  name             = "example-stream"
  shard_count      = 1
}

# Glue Database and Table
resource "aws_glue_catalog_database" "analytics" {
  name = "analytics_db"
}

resource "aws_glue_catalog_table" "events" {
  name          = "events"
  database_name = aws_glue_catalog_database.analytics.name
}

# Backup Vault
resource "aws_backup_vault" "example" {
  name        = "example_backup"
}

# GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Config Rule
resource "aws_config_configuration_recorder" "main" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn
}

resource "aws_config_rule" "s3_bucket_versioning" {
  name = "s3-bucket-versioning-enabled"
}

# CodeBuild Project
resource "aws_codebuild_project" "example" {
  name         = "example-project"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:4.0"
    type         = "LINUX_CONTAINER"
  }
}

# Step Functions State Machine
resource "aws_sfn_state_machine" "example" {
  name     = "example-state-machine"
  role_arn = aws_iam_role.step_functions.arn

  definition = <<EOF
{
  "Comment": "Example state machine",
  "StartAt": "HelloWorld",
  "States": {
    "HelloWorld": {
      "Type": "Pass",
      "Result": "Hello, World!",
      "End": true
    }
  }
}
EOF
}

# Cognito User Pool
resource "aws_cognito_user_pool" "users" {
  name = "example-users"
}

# AppSync GraphQL API
resource "aws_appsync_graphql_api" "api" {
  name                = "example-api"
  authentication_type = "API_KEY"
}

# IAM Roles (referenced by resources above)
resource "aws_iam_role" "eks_cluster" {
  name = "eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "config" {
  name = "config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "codebuild" {
  name = "codebuild-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "step_functions" {
  name = "step-functions-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

