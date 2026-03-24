provider "aws" {
  region = "ap-northeast-2"
}

provider "aws" {
  alias  = "secondary"
  region = "ap-northeast-1"
}
