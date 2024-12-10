# KB

this is fork repository with KB modifications to improve password rotation  scenario.

NOTE: current KB version is base on origin version 1.5.  

### versioning

custom modifications are held in branches `kb-implementation-<origin version>` where `<origin version>` means version of the origin product version on which out branch is based on.  

E.g; kb-implementation-1.5 means it is a branch based on version 1.5.x of conjur-secret-provider  

The commit from which new relase version is created must have version tag in format:  

`<origin version>-KB.<kb version>`

e.g.  
current relase version `1.5.2-KB.7`  
next relase version base on same origin version will be `1.5.2-KB.8`  


### upgrading

How migrate to newer conjur-secret-provider version:  

- rebase current KB branch on top of new origin version and push it as new `kb-implementation-<origin version>` branch  

or  

- create new `kb-implementation-<origin version>` and cherry-pick or commits from previous `kb-implementation-` branch  

E.g:  
current branch: kb-implementation-1.5  
afer upgrade: kb-implementation-1.6  

also make new release tag e.g: `1.6.2-KB.1` (first KB version on the new origin version)  


### build

```
docker buildx build --platform linux/amd64 --load --tag <docker-registry>/kb-secrets-provider-for-k8s:<versin> . -f ./Dockerfile
```

### relase

- manually build image with release version tag
- push to target docker registry
- create and push git tag on commit from the build has been created (see versioning & upgrade)

________________________________

# Table of Contents

- [Table of Contents](#table-of-contents)
- [CyberArk Secrets Provider for Kubernetes](#cyberark-secrets-provider-for-kubernetes)
  - [Supported services](#supported-services)
  - [Using This Project With Conjur Open Source](#using-secrets-provider-for-k8s-with-conjur-open-source)
  - [Methods for Configuring Secrets Provider](#methods-for-configuring-cyberark-secrets-provider)
  - [Enabling Tracing](#enabling-tracing)
- [Releases](#releases)
  - [Stable release definition](#stable-release-definition)
- [Development](#development)
- [Documentation](#documentation)
- [Community](#community)
- [License](#license)

# CyberArk Secrets Provider for Kubernetes

The CyberArk Secrets Provider for Kubernetes provides Kubernetes-based
applications with access to secrets that are stored and managed in Conjur.

## Consuming Secrets from CyberArk Secrets Provider

Using the CyberArk Secrets Provider, your applications can easily consume
secrets that have been retrieved from Conjur in one of two ways:

- **Using Kubernetes Secrets:** The Secrets Provider can populate Kubernetes
  Secrets with secrets stored in Conjur. This is sometimes referred to as
  **"K8s Secrets"** mode.
- **Using Secrets files:** The Secrets Provider can generate initialization or
  credentials files for your application based on secrets retrieved from
  Conjur, and it can write those files to a volume that is shared with your
  application container. This is referred to as the Secrets Provider
  **"Push to File"** mode. For more information, see the
  [Secrets Provider Push-to-File guide](PUSH_TO_FILE.md).

## Deployment Modes

The Secrets Provider can be deployed into your Kubernetes cluster in one
of two modes:

- **As an init container:** The Secrets Provider can be deployed as a
  Kubernetes init container for each of your application Pods that requires
  secrets to be retrieved from Conjur. This configuration allows you to employ
  Conjur policy that authorizes access to Conjur secrets on a
  per-application-Pod basis.

- **As a standalone application container (Kubernetes Job):**
  The Secrets Provider can be deployed as a separate, application container
  that runs to completion as part of a Kubernetes Job. In this mode, the
  Secrets Provider can support delivery of Conjur secrets to multiple
  application Pods. In this mode, you would use Conjur policy that authorizes
  access to Conjur secrets on a per-Secrets-Provider basis.

  The [Secrets Provider Helm chart](helm) can be used to deploy the
  Secrets Provider in standalone application mode.

- **As a sidecar to enable [secrets rotation.](ROTATION.md)**

__NOTE: If you are using the Secrets Provider "Push to file" mode, the
  Secrets Provider must be deployed as an init or sidecar container, since these modes
  makes use of shared volumes to deliver secrets to an application.__

## Supported Services
- Conjur Enterprise 11.1+

- Conjur Open Source v1.4.2+

## Supported Platforms
- GKE

- K8s 1.11+

- Openshift v4.6-v4.8 _*(Conjur Enterprise only)*_

## Using secrets-provider-for-k8s with Conjur Open Source 

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we 
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS 
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html). 
Conjur maintainers perform additional testing on the suite release versions to ensure 
compatibility. When possible, upgrade your Conjur version to match the 
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm); 
when using integrations, choose the latest suite release that matches your Conjur version. For any 
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

## Methods for Configuring CyberArk Secrets Provider

There are several methods available for configuring the  CyberArk Secrets
Provider:

- **Using Pod Environment Variables:** The Secrets Provider can be configured
  by setting environment variables in a Pod manifest. To see a description of
  the Secrets Provider environment variables, and an example manifest in the
  [Set up Secrets Provider as an Init Container](https://docs.conjur.org/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-secrets-provider-ic.htm#SetupSecretsProviderasaninitcontainer)
  section of the Secrets Provider documentation (expand the collapsible
  section in Step 6 of this guide to see details).

- **Using Pod Annotations:** The Secrets Provider can be configured by setting
  [Pod Annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/)
  in a Pod manifest. For details on how Annotations can be used to configure
  the Secrets Provider, see the
  [Secrets Provider Push-to-File guide](PUSH_TO_FILE.md).

- **Using the [Secrets Provider Helm chart](helm) (Standalone Application Mode Only)**
  If you are using the Secrets Provider in standalone application mode, then
  you can configure the Secrets Provider by setting Helm chart values and
  deploying Secrets Provider using the [Secrets Provider Helm chart](helm).

Some notes about the different configuration methods:

1. For a setting that can be configured either by Pod Annotation or by
   environment variable, a Pod Annotation configuration takes precedence
   over the corresponding environment variable configuration.
1. If you are using the Secrets Provider in Push-to-File mode, then the
   Secrets Provider must be configured via Pod Annotations.
1. If you are using the Secrets Provider in Kubernetes Secrets mode, it
   is recommended that you use environment variable settings to configure
   the Secrets Provider.

## Enabling Tracing

Tracing of CyberArk Secrets Provider for Kubernetes is available using the [OpenTelemetry](https://opentelemetry.io/) standard.
Tracing is disabled by default. You can enable tracing using either Pod Annotations or environment variables.
To enable traces appended to the init container's logs, add the annoation `conjur.org/log-traces: true`
to the Pod manifest, or set the `LOG_TRACES` environment variable to `true`.
To instead export the traces to a Jaeger server, use the following annotation:
`conjur.org/jaeger-collector-url: http://<jaeger-collector-host>/api/traces` or use the `JAEGER_COLLECTOR_URL` environment variable.
Traces will include errors to assist in troubleshooting.

# Releases

The primary source of CyberArk Secrets Provider for Kubernetes releases is our [Dockerhub](https://hub.docker.com/repository/docker/cyberark/secrets-provider-for-k8s).

When we release a version, we push the following images to Dockerhub:
1. Latest
1. Major.Minor.Build
1. Major.Minor
1. Major

We also push the Major.Minor.Build image to our [Red Hat registry](https://catalog.redhat.com/software/containers/cyberark/secrets-provider-for-k8s/5ee814f0ac3db90370949cf0).

# Builds

We push the following tags to Dockerhub:

*Edge* - on every successful main build an edge tag is pushed (_cyberark/secrets-provider-for-k8s:edge_).

*Latest* - on every release the latest tag will be updated (_cyberark/secrets-provider-for-k8s:latest_). This tag means the Secrets Provider for Kubernetes meets the stability criteria detailed in the following section.
 
*Semver* - on every release a Semver tag will be pushed (_cyberark/secrets-provider-for-k8s:1.1.0_). This tag means the Secrets Provider for Kubernetes meets the stability criteria detailed in the following section.

## Stable release definition

The CyberArk Secrets Provider for Kubernetes is considered stable when it meets the core acceptance criteria:

- Documentation exists that clearly explains how to set up and use the provider and includes troubleshooting information to resolve common issues.
- A suite of tests exist that provides excellent code coverage and possible use cases.
- The CyberArk Secrets Provider for Kubernetes has had a security review and all known high and critical issues have been addressed.
Any low or medium issues that have not been addressed have been logged in the GitHub issue backlog with a label of the form `security/X`
- The CyberArk Secrets Provider for Kubernetes is easy to setup.
- The CyberArk Secrets Provider for Kubernetes is clear about known limitations and bugs, if they exist.

# Development

We welcome contributions of all kinds to CyberArk Secrets Provider for Kubernetes. For instructions on
how to get started and descriptions of our development workflows, see our [contributing guide](CONTRIBUTING.md).

# Documentation
You can find official documentation on [our site](https://docs.conjur.org/Latest/en/Content/Integrations/k8s-ocp/cjr-secrets-provider-lp.htm).

# Community

Interested in checking out more of our open source projects? See our [open source repository](https://github.com/cyberark/)!

# License

The CyberArk Secrets Provider for Kubernetes is licensed under the Apache License 2.0 - see [`LICENSE`](LICENSE.md) for more details.
