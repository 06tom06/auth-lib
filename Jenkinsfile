properties(
    [buildDiscarder(logRotator(numToKeepStr: '3', daysToKeepStr: '3'))]
)
node('jdk11') {
	try {
		checkout scm
		withMaven(maven: 'M3', mavenSettingsConfig: 'mt-mvn-global-settings') {
			stage('Deploy') {
				sh 'mvn -f pom.xml clean deploy --fail-at-end -U -Pmt,!salt'
				notifyBuild("Build - Finished")
			}
		}
	} catch (e) {
		echo "FATAL: $e"
		currentBuild.result = 'FAILURE'
	} finally {
		notifyBuild()
	}
}

def notifyBuild(String message = '') {
    def result = currentBuild.result ? currentBuild.result : "SUCCESS"
	def summary = "[${result}] ${env.JOB_BASE_NAME} #${env.BUILD_NUMBER}: ${message} ${env.RUN_DISPLAY_URL}"
 	sh """curl -s -i -X POST -d "payload={\\"text\\": \\"${summary}\\"}" https://mattermost.tools-test.it-factory.prod.lan/hooks/chk3oaa1r7gctnojn35q3itnpw > /dev/null"""
}