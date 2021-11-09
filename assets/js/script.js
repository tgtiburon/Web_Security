
console.log("script.js loaded!");


// Variables
const vTotalInfo = '8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a';




// Functions


const initialLoad = () => {


}//end initialLoad()
const webSiteGetID  = () => {

  
   
    let myRequestURL = "https://www.virustotal.com/api/v3/urls";
   
    let formData = new FormData();
    formData.append('url', 'www.google.com');

    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
    console.log(formData);
    console.log(myHeaders);
 
    myRequestObject = {
        method: 'POST',
        headers: myHeaders,
       
        body: formData,
        mode: 'cors'
           
    }

    console.log("myRequestObject below:")
    console.log(myRequestObject);

   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
    console.log(response);
        if(response.ok) {
          
            response.json().then(function(data) {
                console.log(data); 
                console.log(response.status);
                let analysisID = data.id;
                console.log("analysisID = " + analysisID)
            
            });

   
        } else {
            console.log("It worked!");
            console.log(response.status);
            // localStorage.setItem("webSiteID", JSON.stringify(webSiteID));


        }
    });


};//End websiteGetID()

const webSiteScan = () => {

    
}// end webSiteScan


$("body").on("click", "#testButton", function() {
    console.log(this);
});



// Might use JQUERY instead
const buttonHandler = (event) => {
    console.log(event);
  
         
};




// Function calls


initialLoad();




// Listeners
document.addEventListener("click", buttonHandler);


