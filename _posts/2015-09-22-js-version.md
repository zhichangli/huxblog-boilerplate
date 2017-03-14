---
layout:     post
title:      "TAINT ANALYSIS ADDED TO FINDBUGS"
subtitle:   "before my contribution almost all taint sinks were reported in practice"
date:       2017-03-14
author:     "Lee"
header-img: "img/taint-bg.png"
tags:
    - FindBugs
    - Find-Sec-Bug
    - Injection
    - Taint Analysis
    - Sinks
---

[Find-Sec-Bugs](https://github.com/find-sec-bugs/find-sec-bugs) 是一款FindBugs的插件，专用来对代码进行白盒安全扫描，除了保留FindBugs原有扫描模式外，还创新性提出了Taint Analysis方式 , 用作者的话来说 "but before my contribution almost all taint sinks were reported in practice"


目前国内关于find-sec-bugs的中文文档不多，因工作需要翻译了一篇，时间仓促，略粗糙，抛砖引玉


> 英文原链接：[TAINT ANALYSIS ADDED TO FINDBUGS](https://www.ysofters.com/2015/08/31/taint-analysis-added-to-findbugs/)

After finishing hard-coded passwords detector, I have focused on improving the detection of the most serious security bugs, which could be found by static taint analysis.
>当完成硬编码密码检测器之后，我致力于通过通过静态污染分析的方法提高对最严重安全漏洞的检测

SQL injection, OS command injection and Cross-site scripting (XSS)are placed as top first, second and fourth in CWE Top 25 most dangerous software errors (while well-known buffer overflow, not applicable to Java, is placed third)
>SQL injection, OS command injection and Cross-site scripting (XSS) 这些攻击手段在CWE Top25 最危险的软件错误中分别排名第一，第二和第四，而知名的缓冲区溢出攻击排名第三

Path Traversal, Unvalidated Redirect, XPath injection or LDAP injection are also related types of weaknesses  unvalidated user input can exploit syntax of an interpreter and cause a vulnerability
>Path Traversal, Unvalidated Redirect, XPath injection or LDAP injection 这些也是易攻击点，不合法的用户输入可以利用解释器的语法问题进而导致漏洞的产生

Injections in general are the risk number one in OWASP Top 10 too, so a reliable open-source static analyser for those kinds of weaknesses could really make the world a more secure place
>Injections 通常也是OWASP的十大危险因素之一，所以一个可靠的，用于针对各种注入漏洞进行检测的开源静态分析工具是十分有必要的，它可以让这个世界变得更安全

FindBugs already has detectors for some kinds of injections, but many bugs is missed due to insufficient flow analysis, unknown taint sources and sinks and also targeting zero false positives (even though there are some).
>FindBugs 已经有一些针对注入攻击的检测器，但因为流分析的不够充分，未知的污染源和sinks 规则以及针对零可能性的误报（虽然有一些）等问题而错过了很多漏洞

In contrast, the aim of bug detectors in FindSecurityBugs is to be helpful during security code review and not to miss any vulnerability  there was some effort to reduce false positives, but before my contribution almost all taint sinks were reported in practice.
>相反的是，FindSecurityBugs 的检测器是为了在安全代码审计中变得更有帮助，以便不要错过任何漏洞，在减少漏洞这块是有一定影响和帮助的，但在我贡献这代码之前，大部分的污染检测仅仅只是停留在报告研究阶段

Unfortunately, searching a real problem among many false warnings is quite tedious.
>遗憾的是，在众多错误警告中寻找一个真正的问题是相当枯燥乏味

The aim of the new detection mechanism is to report more high-confidence bugs (with minimum of false positives) than FindBugs detectors plus report lower-confidence bugs with decreased priority not missing any real bugs while having false positives rate much lower than FindSecurityBugs had originally.
>新的检测机制能比Findbugs 的检测器检测出更高可信度的bugs同时不错过任何真正的Bugs,也比最初的FindSecurityBugs 降低更多的误报率

For a reliable detection, we need a good data-flow analysis. I have already mentioned OpcodeStackDetector class in previous articles, but there is a more advanced and general mechanism in FindBugs. We can create and register classes performing a custom data-flow analysis and request those results later in detectors.
>为了更可靠的检测，我们需要一个良好的数据流分析方法，我在之前的文章已经提到过OpcodeStackDetector 这个类，但在FindBugs有一个更高级和通用的机制，我们可以创建和注册一个用来执行自定义数据流分析的一个类，并用这些检测器执行检测获得结果

Methods are symbolically executed after building control flow graph made of blocks of instructions connected by different types of edges (such as goto, ifcmp or exception handling), which are attempted to be pruned for impossible flow.
>当指令块被各种不同类型的线（例如goto,ifcmp或exception）连接所构成的控制流图被构建后，方法就会被执行，这些流程图被视为最小可分割块

We have to create a class to represent facts at different code locations
>因此，我们必须创建一个类来记录在不同代码位置上的一些fact信息

we want to remember some information (called a fact) for every reachable instruction, which can later help us to decide, whether a particular bug should be reported at that location.
>我们要记住每个能够被执行的指令的fact信息，这些信息之后可以帮我们决定是否应该在该位置报告一个可能存在的bug

We need to model effects of instructions and edges on facts, specify the way of merging facts from different flow branches and make everything to work together.
>我们需要模拟指令和边界对fact的效果，以及指定从来自不同流分支的fact合并的方式，并使一切工作正常

Fortunately, there are existing classes designed for extension to make this process easier.
>幸运的是，目前已经有一些扩展类使这一过程变得更容易

In particular, FrameDataflowAnalysis models values in the operand stack and local variables, so we can concentrate on the sub-facts about these values.
>值得注意的一点，FrameDataflowAnalysis对操作栈和局部变量中的值进行建模，因此我们可以主要关注sub-facts的值

The actual fact is then a frame of these sub-facts. This class models effects of instructions by pushing the default sub-fact on the modelled stack and popping the right amount of stack values.
>一个实际的fact是这些sub-facts的一个帧，这个类通过往标准stack上推送默认的sub-fact进而弹出一定数量的stack的值来模拟指令的效果

It also automatically moves sub-facts between the stack and the part of the frame with local variables.
>它同时使用局部变量将sub-facts在堆栈和一部分栈帧间移动

Lets have a look, which classes had to be implemented for taint analysis. If we want to run custom data-flow analysis, a special class implementing IAnalysisEngineRegistrar must be created and referenced from findbugs.xml.
>让我们看一下，哪些类有必要去进行污染分析，如果我们想要使用自定义的数据流分析器，需要有一个自定义的类实现IAnalysisEngineRegistrar ，同时要在findbugs.xml中定义

```
<!-- Registers engine for taint analysis dataflow -->
 <EngineRegistrar class="com.h3xstream.findsecbugs.taintanalysis.EngineRegistrar"/>
```

This simple class (called EngineRegistrar) makes a new instance of TaintDataflowEngine and registers it with global analysis cache.

```
public class EngineRegistrar implements IAnalysisEngineRegistrar {

    @Override
    public void registerAnalysisEngines(IAnalysisCache cache) {
        new TaintDataflowEngine().registerWith(cache);
    }
}
```

Thanks to this, in the right time, method analyze of TaintDataflowEngine (implementing ImethodAnalysisEngine) is called for each method of analyzed code.
>有了这些，TaintDataflowEngine中用于分析的方法会对每个待检查方法的代码进行分析

This method requests objects needed for analysis, instantiates two custom classes (mentioned in next two sentences) and executes the analysis.
>这些用于分析方法需要用来分析的对象实例化两个自定义的类来执行分析操作

```
public class TaintDataflowEngine
    implements IMethodAnalysisEngine<TaintDataflow> {

    @Override
    public TaintDataflow analyze(IAnalysisCache cache)
            throws CheckedAnalysisException {
        CFG cfg = cache.getMethodAnalysis(CFG.class, descriptor);
        DepthFirstSearch dfs = cache
            .getMethodAnalysis(DepthFirstSearch.class, descriptor);
        MethodGen methodGen = cache
            .getMethodAnalysis(MethodGen.class, descriptor);
        TaintAnalysis analysis = new TaintAnalysis(
            methodGen, dfs, descriptor);
        TaintDataflow flow = new TaintDataflow(cfg, analysis);
        flow.execute();
        return flow;
    }

    @Override
    public void registerWith(IAnalysisCache iac) {
        iac.registerMethodAnalysisEngine(TaintDataflow.class, this);
    }
}
```

TaintDataflow (extending Dataflow) is really simple and used to store results of performed analysis (used later by detectors).
>TaintDataflow（继承自Dataflow）非常简单，用于存储执行分析的结果（稍后由检测器使用）

```
public class TaintDataflow
        extends Dataflow<TaintFrame, TaintAnalysis> {

    public TaintDataflow(CFG cfg, TaintAnalysis analysis) {
        super(cfg, analysis);
    }
}
```

TaintAnalysis (extending FrameDataflowAnalysis) implements data-flow operations on TaintFrame but it mostly delegates them to other classes.
>TaintAnalysis（继承自FrameDataflowAnalysis）在TaintFrame上实现数据流操作，但是它大多将它们委托给其他类

```
public class TaintAnalysis
        extends FrameDataflowAnalysis<Taint, TaintFrame> {

    private final MethodGen methodGen;
    private final TaintFrameModelingVisitor visitor;

    public TaintAnalysis(MethodGen methodGen, DepthFirstSearch dfs,
            MethodDescriptor descriptor) {
        super(dfs);
        this.methodGen = methodGen;
        this.visitor = new TaintFrameModelingVisitor(
            methodGen.getConstantPool(), descriptor);
    }

    @Override
    protected void mergeValues(TaintFrame frame, TaintFrame result,
            int i) throws DataflowAnalysisException {
        result.setValue(i, Taint.merge(
            result.getValue(i), frame.getValue(i)));
    }

    @Override
    public void transferInstruction(InstructionHandle handle,
            BasicBlock block, TaintFrame fact)
            throws DataflowAnalysisException {
        visitor.setFrameAndLocation(
            fact, new Location(handle, block));
        visitor.analyzeInstruction(handle.getInstruction());
    }

    // some other methods
}
```

TaintFrame is just a concrete class for abstract Frame<Taint>.

```
public class TaintFrame extends Frame<Taint> {

    public TaintFrame(int numLocals) {
        super(numLocals);
    }
}
```

Effects of instructions are modelled by TaintFrameModelingVisitor (extending AbstractFrameModelingVisitor) so we can code with the visitor pattern again.
>指令的效果由TaintFrameModelingVisitor（继承自AbstractFrameModelingVisitor）建模，因此我们可以再次使用访问者模式进行编码

```
public class TaintFrameModelingVisitor
    extends AbstractFrameModelingVisitor<Taint, TaintFrame> {

    private final MethodDescriptor methodDescriptor;

    public TaintFrameModelingVisitor(ConstantPoolGen cpg,
            MethodDescriptor method) {
        super(cpg);
        this.methodDescriptor = method;
    }

    @Override
    public Taint getDefaultValue() {
        return new Taint(Taint.State.UNKNOWN);
    }

    @Override
    public void visitACONST_NULL(ACONST_NULL obj) {
        getFrame().pushValue(new Taint(Taint.State.NULL));
    }

    // many more methods
}
```

The taint fact  information about a value in the frame (stack item or local variable) is stored in a class called just Taint.
>关于帧中（堆栈项或局部变量）被污染的fact的信息存储在一个称为Taint的类中

The most important piece of information in Taint is the taint state represented by an enum with values TAINTED, UNKNOWN, SAFE and NULL.
>Taint中最重要的信息是由值为TAINTED，UNKNOWN，SAFE和NULL的枚举表示的污染状态

TAINTED is pushed for invoke instruction with a method call configured to be tainted (e.g. getParameter from HttpServletRequest or readLine from BufferedReader)
>TAINTED被用于调用一个让其被配置为被污染的指令（例如，来自HttpServletRequest的getParameter或来自BufferedReader的readLine）

SAFE is stored for ldc (load constant) instruction, NULL for aconst_null and UNKNOWN is a default value (this description is a bit simplified).
>SAFE存储为ldc（加载常量）指令，NULL为aconst_null，UNKNOWN为默认值（此描述有点简化）

Merging of taint states is defined such that if we could compare them as TAINTED > UNKNOWN > SAFE > NULL, then merge of states is the greatest value (e.g. TAINTED SAFE = TAINTED).
>污染状态合并的方式已被定义，因此我们通过以下优先级比较他们 AINTED > UNKNOWN > SAFE > NULL ，状态的合并是最大值（例如TAINTED SAFE = TAINTED）

Not only this merging is done where there are more input edges to a code block of control flow graph, but I have also implemented a mechanism of taint transferring methods.
>这种合并方式不仅是在控制流图的代码块上有更多输入的情况下完成的，而且我还实现了一种污染传送方法的机制

For example, consider calling toLowerCase method on a String before passing it to a taint sink  instead of pushing a default value (UNKNOWN), we can copy the state of the parameter not to forget the information.
>例如，考虑在将字符串传递给taint sink之前调用toLowerCase方法， 而不是推送默认值（UNKNOWN），我们可以复制参数的状态而不丢掉其原本的信息

Merging is also done in more complicated examples such as for append method of StringBuilder  the taint state of the argument is merged with the taint state of StringBuilder instance and returned to be pushed on the modelled stack.
>合并同时也在更复杂的例子中解决，例如对于StringBuilder的append方法，参数的taint State会和StringBuilder的实例进行合并，并返回以压入建模的栈中

There were two problems with taint state transfer which had to be solved.
>在污染状态转移中有两个问题必须被解决

First, taint state must be transferred directly to mutable classes too, not only to their return values (plus the method can be void).
>首先，污点状态必须直接传递给可变类，不仅仅是它们的返回值（加上方法可以是void）

Not only we set the taint state for an object when it is being seen for the first time in the analysed method and then the state is copied, but we also change it according to instance methods calls.
>当某个对象第一次被分析到且被设置了污染状态后，在之后的操作中，我们不应该只是单纯的复制他的状态而是要根据被方法使用的情况动态修改它的污染状态

For example, StringBuilder is safe, when a new instance is created with non-parametric constructor, but it can taint itself by calling its append method.
>例如，当实例化一个无参构造函数的StringBuilder时，它是安全的，而调用它自身的append方法时却被污染了

If only methods with safe parameters are called, the taint state of StringBuilder object remains safe too.
>如果参数是安全的，那么StringBuilder对象也依旧是安全的

For this reason, effect of load instructions is modified to mark index of loaded local variable to Taint instance of corresponding stack item.
>为此，修改加载指令的效果以将加载的局部变量的索引标记为相应堆栈项的Taint实例

Then we can transfer taint state to a local variable with index stored in Taint for specified methods in mutable classes.
>之后对于可变类中的一些特定方法，我们可以将污染状态转移到局部变量，同时将索引存储在Taint中

Second, taint transferring constructors(methods <init> in bytecode) must be handled specifically, because of the way of creating new objects in Java. Instruction new is followed by dup and invokespecial, which consumes duplicated value and initializes the object remaining at the top of the stack.
>第二点，由于在Java中创建新对象的方式，必须定义处理污染转移的构造函数（字节码中的方法<init>）。 指令new之后是dup和invokespecial，它消耗重复的值并初始化剩余在堆栈顶部的对象

Since the new object is not stored in any variable, we must transfer the taint value from merged parameters to the stack top separately.
>由于新对象不存储在任何变量中，因此我们必须分别将合并参数中的污染值传递到堆栈顶部

Bugs related to taint analysis are identified by TaintDetector (implementing Detector)
>与污染相关的Bug由TaintDetector进行分析（实现Detector接口）

For better performance, before methods of some class are analyzed, constant pool (part of the class file format with all needed constants) is searched and the analysis continues only if there are references for some taint sinks.
>为了更好的性能，在分析某些类的方法之前，搜索常量池，当存在对一些taint sink文件的引用时分析才继续

Then TaintDataflow instance is loaded for each method and locations of its control flow graph are iterated until taint sink method is found.
>TaintDataflow会对每一个方法以及控制流程图中每个节点进行扫描迭代，直到找到taint sink文件中定义有的方法

This means, we find all invoke instructions used in a currently analysed method and check, whether the called methods are related to the searched weaknesses.
>这意味着，我们可以分析到在待分析方法中用到的所有指令，通过检查可以知道这些被调用的方法中是否存在我们要找的存在风险的方法

Facts (instances of Taint class) from TaintDataFlow are extracted for each sink parameter of a sink method.
>从sink方法的每个sink参数提取TaintDataFlow的Facts

Bug is reported with high confidence (and priority), if the taint state is TAINTED, with medium confidence for UNKNOWN taint state and with low confidence for SAFE and NULL (just for the case of a bad analysis, these warnings are not normally shown anywhere).
>如果污染状态为TAINTED，对于UNKNOWN污染状态具有中等置信度，对于SAFE和NULL具有低置信度，则以高置信度（和优先级）报告错误（仅对于坏分析的情况，这些警告通常不在任何地方示出）

Taint class also contains references for taint source locations, so these are shown in bug reports to make review easier you should see a path between taint sources and the taint sink.
>Taint类还包含对污点源位置的引用，因此这些在错误在报告中显示以使审核更容易，基于此，你应该看到在污点源和污点sink之间的联系

TaintDetector itself is abstract, so it must be extended to detect concrete weakness types (like command injection) and InjectionSource interface implemented to specify taint sinks (the name of the interface is a bit misleading) and items in a constant pool to specify candidate classes.
>TaintDetector本身是抽象的，因此它必须被继承来检测具体的弱类型（如命令注入）和实现的InjectionSource接口来指定污点sink（接口的名称有点误导）以及常量池中的项目来指定待检测的类

```
public class CommandInjectionDetector extends TaintDetector {

    public CommandInjectionDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    public InjectionSource[] getInjectionSource() {
        return new InjectionSource[] {new CommandInjectionSource()};
    }
}
```

CommandInjectionSource overwrites method getInjectableParameters, which returns an instance of InjectionPoint containing parameters, that cannot be tainted, and the weakness type to report. Boolean method isCandidate looks up constant pool for the names of taint sink classes and return true if present.
>CommandInjectionSource重写方法getInjectableParameters，它返回一个不能被污染的包含参数的InjectionPoint实例，以及要于报告的缺陷类型。 布尔方法isCandidate查找常量池以获取污点sink类的名称，并返回true（如果找到的话）

TaintDetector is currently used to detect command, SQL, LDAP and script (for evalmethod of ScriptEngine) injections and unvalidated redirect. More bug types and taint sinks should follow soon. Test results are looking quite promising so far.
>TaintDetector当前用于检测command，SQL，LDAP和脚本（ScriptEngine的evalmethod）注入和不合法的重定向。 更多的bug类型和污点sinks应该很快得到补充。 到目前为止，测试结果看起来很有帮助

Inter-procedural analysis (not restricted to a method scope) should be the next big improvement, which could make this analysis really helpful. Then everything should be tested with a large amount of real code to iron out the kinks. You can see the discussed classes in taintanalysis package and try the new version of FindSecurityBugs.
>Inter-procedural analysis（不只局限于方法范围）应该是下一个重大提高，这可以使此分析真正有用。 然后一切都应该用大量的实际代码进行测试。 你可以在taintanalysis包中看到讨论的类，并尝试新版本的FindSecurityBugs


