FIDATA Infrastructure
---------------------

This repository contains:
*	Scripts to build immutable servers with Packer & Vagrant & Chef
	*	Kernel images - clean installs without any provisioners
	*	Base images
	*	Jenkins master
	*	Jenkins slaves

	Targets:
	*	Vagrant boxes for VirtualBox - testing environment
	*	Amazon AMIs - production environment

*	Scripts to deploy infrastructure with Terraform

### Prerequisites:
*	VirtualBox (5.1.18)
*	Packer
*	AWS CLI
*	Vagrant
*	Terraform
*	Ruby & Bundler

	Gradle doesn't run `bundle update` if gems are already installed
	(i.e. `gems.locked` file exists). When necessary you have to run it
	manually:
	```
	bundle update
	```

### Workflow:

1.	Clean and build kernel VirtualBox images
	```
	./gradlew clean-kernel-*-vbox
	./gradlew build-kernel-*-vbox
	```
	There is a separate task for each image

2.	Deploy common Terraform resources, build base VirtualBox images &
Vagrant boxes
	```
	./gradlew build-base
	```

3.	Test build toolkit used for Jenkins slaves:
	```
	./gradlew kitchenTest-BuildToolkit
	```

4.	Build Jenkins slave AMIs:
	```
	./gradlew build-JenkinsSlaves
	```

5.	Test Jenkins Master:
	```
	./gradlew kitchenTest-JenkinsMaster-vbox
	./gradlew kitchenTest-JenkinsMaster-amazon
	```

6.	Build JenkinsMaster production AMI:
	```
	./gradlew build-JenkinsMaster
	```

7.	Deploy instances:
	```
	./gradlew deploy
	```

### Making changes:
Check code:
```
gradlew --continue check
```

### Packer, Vagrant & Chef scripts are based on:
1.	[Bento](https://chef.github.io/bento/)

2.	[Boxcutter](https://github.com/boxcutter)

3.	[joefitzgerald/packer-windows](https://github.com/joefitzgerald/packer-windows)

4.	[innvent/parcelles](https://github.com/innvent/parcelles)


### Credits (Additional reading)
1.	Immutable Servers:
	*	[Kief Morris. ImmutableServer](http://martinfowler.com/bliki/ImmutableServer.html)
	*	[Florian Motlik. Immutable Servers and Continuous Deployment](https://blog.codeship.com/immutable-server/)
2.	[Alvaro Miranda Aguilera: Idea about separate minimal (kernel) image](https://groups.google.com/d/msg/packer-tool/S0h4CFkgN2Y/fsAzpiBhivoJ)
3.	[MistiC: Nested `Berksfile`s](https://habrahabr.ru/company/epam_systems/blog/221791/)
4.	[StephenKing: Method to install Jenkins plugins](https://github.com/chef-cookbooks/jenkins/issues/534#issuecomment-265145360)
5.	[tknerr: `Vagrantfile` to enable `vagrant-cachier`](https://github.com/test-kitchen/kitchen-vagrant/issues/186#issuecomment-133942255)


------------------------------------------------------------------------
Copyright © 2015-2017  Basil Peace

This is part of FIDATA Infrastructure.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.