---
layout:     post
title:      "FindSecBugs源码分析"
subtitle:   "FindSecBugs是FindBugs的安全扫描扩展部分"
date:       2017-03-17
author:     "Lee"
header-img: "img/taint-bg.png"
tags:
    - FindBugs
    - Find-Sec-Bug
    - Injection
    - Taint Analysis
    - Sinks
---

FindSecBugs作为FindBugs的安全扫描扩展部分，同样基于JAVA的字节码对class文件进行扫描检测

工程源码地址： [Find-Sec-Bugs](https://github.com/find-sec-bugs/find-sec-bugs)

> [ 深入JVM字节码执行引擎](http://blog.csdn.net/dd864140130/article/details/49515403)

FindSecBugs工程分为四个子项目
* findbugs-test-util: Utility classes that make unit test writing shorter.
* plugin: Main project containing the FindBugs detectors.
* plugin-deps: This provided Mock version of popular Java librairies. Avoid the necessity to download all the libraries used in FindSecurityBugs sample code.
* website: This project contains scripts used to generated the static website hosted on GitHub pages.

FindSecBugs中所有的detector均是用于安全的检测，放在plugin项目中，通过对detector实现方式总结,发现整个工程的 *Detector 代码继承和实现关系可归纳为以下几种：

1.继承OpcodeStackDetector类
构造函数
重写sawOpcode

2.实现Detector接口
构造函数
重写visitClassContext

3.继承BasicInjectionDetector类
构造函数
重写getPriority

4.实现InjectionSource接口
重写getInjectableParameters

5.继承LegacyInjectionDetector类
构造函数
重写getInjectionSource

6.继承OpcodeStackDetector类
构造函数
重写visit(JavaClass javaClass)
重写visitAfter(JavaClass obj)
重写visit(Method method)
重写sawOpcode

7.继承BasicInjectionDetector类
构造函数
重写getPriorityFromTaintFrame(TaintFrame fact, int offset)
重写InjectionPoint getInjectionPoint(InvokeInstruction invoke, ConstantPoolGen cpg,InstructionHandle handle)

8.继承BasicInjectionDetector类
构造函数
重写getPriority
重写shouldAnalyzeClass(ClassContext classContext)

可见，进行安全检测的Detector主要分为两种，继承OpcodeStackDetector类和继承BasicInjectionDetector类
通过阅读代码，发现事实也的确如此，OpcodeStackDetector由FindBugs提供，具体的检测规则可直接在重写函数sawOpcode中硬编码，此种方式相对
来说比较易懂，规则清晰明了

> 小技巧：可以通过包名判断某个类的具体提供方，edu归属FindBugs,h3xstream归属findSecBugs

> FindBugs [官方API查询文档](http://findbugs.sourceforge.net/api/)

下面重点阐述继承BasicInjectionDetector类的检测方式，这种方式由FindSecBugs作者提出，为了实现这种更高效检测的方式
作者新写了一个分析引擎和用于Detector继承的抽象类，重点关注以下这些类

A: ![](https://github.com/zhichangli/zhichangli.github.io/blob/master/img/findSecBugs/h3x%E8%87%AA%E5%AE%9A%E4%B9%89%E6%8A%BD%E8%B1%A1detector01.png?raw=true)
B: ![](https://github.com/zhichangli/zhichangli.github.io/blob/master/img/findSecBugs/h3x%E8%87%AA%E5%AE%9A%E4%B9%89%E6%8A%BD%E8%B1%A1detector02.png?raw=true)
C: ![](https://github.com/zhichangli/zhichangli.github.io/blob/master/img/findSecBugs/taintanalysis.png?raw=true)

AB归为一部分，为用于被自定义Detector实现的抽象类，C为作者自定义的检测引擎，为了更好解释自定义检测引擎的编码结构，引入下图

> 按理UML图更适合，但允许我任性选择自己喜欢的图形吧，这里约定一下，除了菱形表示函数外，其他都为类，椭圆形为矩形的接口或抽象类

* New 一个EngineRegistrar实现IAnalysisEngineRegistrar(edu)用来注册一个污染检测引擎TaintDataflowEngine
* TaintDataflowEngine实现IMethodAnalysisEngine(edu)接口,这里主要关注分析的方法analyze(IAnalysisCache cache, MethodDescriptor descriptor)
* analyze返回TaintDataflow，其中进行实际分析的工作的是TaintAnalysis类
* TaintAnalysis类继承FrameDataflowAnalysis(edu)，关注其中的visitor变量，该变量为TaintFrameModelingVisitor的实例
* TaintFrameModelingVisitor是真正以观察者模型进行分析的实施类，继承AbstractFrameModelingVisitor(edu)，关注TaintFrameModelingVisitor中的visitLDC(),visitLDC2_M(),visitSIPUSH()等系列方法，这些方法具体访问的字节码可参与JVM相关资料
* 看代码时会发现TaintDataFlow,TaintFrame,Taint这三个对象在以上所涉及到类中的各函数间流转，最终引擎返回的结果是TaintDataFlow对象，这三者的关系是TaintAnalysis检测TaintFrame得到一系列Taint结果，
这些Taint结果被包装成TaintDataFlow返回
* 以上，这一系列的Taint*构成了一个全新的检测引擎

> [JVM](https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html)

D: ![](https://github.com/zhichangli/zhichangli.github.io/blob/master/img/findSecBugs/findSecBugsEngine.png?raw=true)

* CrlfLogInjectionDetector 继承于 BasicInjectionDetector 继承于 AbstractInjectionDetector 继承于 AbstractTaintDetector 实现 Detector(由FindBugs edu提供)
* AbstractTaintDetector中通过调用上面提到的作者新建的解析引擎进而获得TaintDataflow结果返回用于分析

E: ![](https://github.com/zhichangli/zhichangli.github.io/blob/master/img/findSecBugs/FindSecBugsDetector.png?raw=true)

当有了以上的概念后，相信再看这篇就很容易理解了 [TAINT ANALYSIS ADDED TO FINDBUGS](https://zhichangli.github.io/zhichangli.github.io/2017/03/14/findSecBugs-translate/)

小结：


