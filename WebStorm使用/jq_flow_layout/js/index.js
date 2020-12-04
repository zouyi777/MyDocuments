window.onload=function(){
	wallterfall("main","box");
	var dataInit={"data":[{"src":"8.jpg"},{"src":"4.jpg"},{"src":"5.jpg"},{"src":"6.jpg"},{"src":"7.jpg"}]};
	window.onscroll=function(){
		if(checkScrollSlide()){
			//��̬��Ӵ����ݵ�Ԫ��
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

//ʵ���ٲ���Ч��
function wallterfall(parent,clasName){
	//��mian�������е�classnameΪbox��Ԫ��ȡ����
	var mParent=document.getElementById(parent);
	var boxs=getByClass(mParent,clasName);
	//��������ҳ����ʾ��������ҳ����/box��ȣ�
	var mBoxsW=boxs[0].offsetWidth;
	var clos=Math.floor(document.documentElement.clientWidth/mBoxsW);
	//����main�Ŀ��
	mParent.style.cssText="width:"+mBoxsW*clos+"px;margin:0 auto";
	var rowHs=new Array();
	for(var j=0;j<boxs.length;j++){
		if(j<clos){
			rowHs.push(boxs[j].offsetHeight);//����һ�еĺ��ӵĸ߶ȴ洢������
		}else {
			var minH=Math.min.apply(null,rowHs);//���һ�еĺ��ӵĸ߶���Сֵ
			var index=getMinHeightIndex(rowHs,minH);//��һ�и߶���С���Ǹ����ӵ�����
			boxs[j].style.position="absolute";
			boxs[j].style.top=minH+"px";//���õڶ��к��Ӷ����߾�
			boxs[j].style.left=index*mBoxsW+"px";//���õڶ��к�����߾�
			rowHs[index]+=boxs[j].offsetHeight;//�޸���Сֵ���ӵĸ߶�
		}
	}
	
}
//ͨ��class������ȡԪ��
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
//��ȡ��С�ĸ߶ȵ�����
function getMinHeightIndex(rowHs,minH){
	for(var i=0;i<rowHs.length;i++){
		if(rowHs[i]==minH){
			return i;
		}
	}
	
}
//�жϹ����Ƿ��˼������ݵ�ʱ��
function checkScrollSlide(){
	//��mian�������е�classnameΪbox��Ԫ��ȡ����
	var mParent=document.getElementById("main");
	var boxs=getByClass(mParent,"box");
	//��ȡ���һ��Ԫ�ص�һ����붥���ľ���top
	var lastHalfBoxTop=boxs[boxs.length-1].offsetTop+Math.floor(boxs[boxs.length-1].offsetHeight/2);
	//����ҳ������ľ���(���ݻ���ģʽ�ͱ�׼ģʽ)
	var srcollTop=document.body.scrollTop || document.documentElement.scrollTop;
	//������������ĸ߶�(���ݻ���ģʽ�ͱ�׼ģʽ
	var browserVisiableH=document.body.clientHeight || document.documentElement.clientHeight;
	return (lastHalfBoxTop<srcollTop+browserVisiableH)?true:false;
}