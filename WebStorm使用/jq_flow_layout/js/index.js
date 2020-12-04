window.onload=function(){
	wallterfall("main","box");
	var dataInit={"data":[{"src":"8.jpg"},{"src":"4.jpg"},{"src":"5.jpg"},{"src":"6.jpg"},{"src":"7.jpg"}]};
	window.onscroll=function(){
		if(checkScrollSlide()){
			//动态添加带数据的元素
			var mainDiv=document.getElementById("main");
			for(var i=0;i<dataInit.data.length;i++){
				var boxDiv=document.createElement("div");
				boxDiv.className="box";
				mainDiv.appendChild(boxDiv);
				var picDiv=document.createElement("div");
				picDiv.className="pic";
				boxDiv.appendChild(picDiv);
				var mImg=document.createElement("img");
				mImg.src="images/"+dataInit.data[i].src;
				picDiv.appendChild(mImg);
			}
			wallterfall("main","box");
		}
	}
}

//实现瀑布流效果
function wallterfall(parent,clasName){
	//将mian下面所有的classname为box的元素取出来
	var mParent=document.getElementById(parent);
	var boxs=getByClass(mParent,clasName);
	//计算整个页面显示的列数（页面宽度/box宽度）
	var mBoxsW=boxs[0].offsetWidth;
	var clos=Math.floor(document.documentElement.clientWidth/mBoxsW);
	//设置main的宽度
	mParent.style.cssText="width:"+mBoxsW*clos+"px;margin:0 auto";
	var rowHs=new Array();
	for(var j=0;j<boxs.length;j++){
		if(j<clos){
			rowHs.push(boxs[j].offsetHeight);//将第一行的盒子的高度存储到数据
		}else {
			var minH=Math.min.apply(null,rowHs);//求第一行的盒子的高度最小值
			var index=getMinHeightIndex(rowHs,minH);//第一行高度最小的那个盒子的索引
			boxs[j].style.position="absolute";
			boxs[j].style.top=minH+"px";//设置第二行盒子顶部边距
			boxs[j].style.left=index*mBoxsW+"px";//设置第二行盒子最边距
			rowHs[index]+=boxs[j].offsetHeight;//修改最小值盒子的高度
		}
	}
	
}
//通过class类名获取元素
function getByClass(parent,clasName){
	var mArr=new Array(),
		mElements=parent.getElementsByTagName("*");
	for(var i=0;i<mElements.length;i++){
		if(mElements[i].className==clasName){
			mArr.push(mElements[i]);
		}
	}
	return mArr;
}
//获取最小的高度的索引
function getMinHeightIndex(rowHs,minH){
	for(var i=0;i<rowHs.length;i++){
		if(rowHs[i]==minH){
			return i;
		}
	}
	
}
//判断滚动是否到了加载数据的时候
function checkScrollSlide(){
	//将mian下面所有的classname为box的元素取出来
	var mParent=document.getElementById("main");
	var boxs=getByClass(mParent,"box");
	//获取最后一个元素的一半距离顶部的距离top
	var lastHalfBoxTop=boxs[boxs.length-1].offsetTop+Math.floor(boxs[boxs.length-1].offsetHeight/2);
	//计算页面滚动的距离(兼容混杂模式和标准模式)
	var srcollTop=document.body.scrollTop || document.documentElement.scrollTop;
	//浏览器可视区的高度(兼容混杂模式和标准模式
	var browserVisiableH=document.body.clientHeight || document.documentElement.clientHeight;
	return (lastHalfBoxTop<srcollTop+browserVisiableH)?true:false;
}