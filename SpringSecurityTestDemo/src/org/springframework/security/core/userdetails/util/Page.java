package org.springframework.security.core.userdetails.util;

/**
 * Description	分页类,只需传入当前页和你的总行数，就可以调用其中的上一页下一页等。
 * @author 		辜凤莲
 * @version		2008/10/01
 */
public class Page {
	/**当前页*/
	private int currentPage;
	/**首页*/
	private int firstPage;
	/**上一页*/
	private int priviousPage;
	/**下一页*/
	private int nextPage;
	/**尾页*/
	private int lastPage;
	/**总页数*/
	private int totalPage;
	/**每页行数*/
	private int pageRows=2;
	/**总行数*/
	private int totalRows;
	
	public int getFirstPage() {
		this.firstPage = 1;
		return firstPage;
	}
	
	public int getLastPage() {
		this.lastPage = this.getTotalPage();
		return lastPage;
	}
	
	public int getNextPage() {
		if(this.currentPage>=this.getTotalPage()){
			this.nextPage=this.getTotalPage();
		}else{
			this.nextPage = this.currentPage+1;
		}
		return nextPage;
	}
	
	public int getPageRows() {
		if(pageRows*this.currentPage>this.getTotalRows()){
			return this.getTotalRows();
		}
		return pageRows*this.currentPage;
	}
	public void setPageRows(int pageRows) {
		this.pageRows = pageRows;
	}
	public int getPriviousPage() {
		if(this.currentPage<=1){
			this.priviousPage = 1;
		}else{
			this.priviousPage = this.currentPage-1;
		}
		return priviousPage;
	}
	public void setPriviousPage(int priviousPage) {
		this.priviousPage = priviousPage;
	}
	
	public int getTotalPage() {
		this.totalPage = (int) Math.ceil(this.totalRows/(double)this.pageRows);
		return this.totalPage;
	}
	
	public int getTotalRows() {
		return totalRows;
	}
	public void setTotalRows(int totalRows) {
		this.totalRows = totalRows;
	}
	public int getCurrentPage() {
		
		if(this.totalRows==0){
			this.currentPage=0;
		}
		
		return currentPage;
	}
	public void setCurrentPage(int currentPage) {
		this.currentPage = currentPage;
	}
	
	/**返回要查询的行*/
	public int getRows(){
		return (this.currentPage-1)*this.pageRows;
	}
}

