// Nightly cloud posture scan. Needs: Pipeline, JUnit, Warnings NG, and AWS Credentials plugins.
// The scanner uses a read-only role (policies/scanner-readonly-policy.json); no write access is ever needed.
pipeline {
  agent { docker { image 'python:3.12-slim' } }
  triggers { cron('H 2 * * *') }
  parameters {
    string(name: 'REGIONS', defaultValue: 'us-east-1,us-west-2', description: 'AWS regions to scan')
    choice(name: 'FAIL_ON', choices: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Fail the build at this severity')
  }
  options { timeout(time: 20, unit: 'MINUTES'); buildDiscarder(logRotator(numToKeepStr: '30')) }
  stages {
    stage('Install') {
      steps { sh 'pip install --no-cache-dir -r requirements.txt' }
    }
    stage('Scan') {
      steps {
        withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-posture-readonly']]) {
          sh '''
            python -m scanner --regions "$REGIONS" --format json,html,sarif,junit \
              --output reports --fail-on "$FAIL_ON"
          '''
        }
      }
    }
  }
  post {
    always {
      junit testResults: 'reports/posture-report.xml', allowEmptyResults: true
      recordIssues tools: [sarif(pattern: 'reports/posture-report.sarif', id: 'posture', name: 'Cloud posture')]
      archiveArtifacts artifacts: 'reports/*', fingerprint: true
    }
  }
}
